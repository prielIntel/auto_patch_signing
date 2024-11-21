import sys
import os
import getpass
from subprocess import check_output
from subprocess import CalledProcessError

try:
    import paramiko
except ModuleNotFoundError as e:
    no_paramiko = True


def signal_error(header, err):
    print("   *****  ****   ****    ***   **** ")
    print("   *      *   *  *   *  *   *  *   *")
    print("   *****  ****   ****   *   *  **** ")
    print("   *      *   *  *   *  *   *  *   *")
    print("   *****  *   *  *   *   ***   *   *")
    print(header)
    print(err)
    input("Hit any key to exit")
    exit(1)


def script_passed():
    print()
    print("   *****   *     ****  ****")
    print("   *   *  * *   *     *    ")
    print("   ****  *****   ***   *** ")
    print("   *     *   *      *     *")
    print("   *     *   *  ****  **** ")


project_dict = {
    "skl": "Skylake",
    "CFL": "Skylake",
    "KBL": "Skylake",
    "CML": "Skylake",
    "skx": "SKX",
    "cnl": "CNL",
    "icl": "IceLake",
    "icx": "IceLakeX",
    "rkl": "IceLake",
    "tgl": "TigerLake",
    "spr": "SapphireRapids",
    "adl": "ADLpatch",
    "rpl": "ADLpatch",
    "mtl": "MTLpatchRSA",
    "lnl": "LNLMpatchRSA",
    "gnr": "GNRpatchRSA",
    "arlh": "ARLpatchRSA",
    "arls": "ARLpatchRSA",
    "ptl": "PTLpatchRSA",
    "wcl": "PTLpatchRSA",
}

algo_dict = {
    "Skylake": "rc4",
    "SKX": "rc4",
    "CNL": "rc4",
    "IceLake": "aes",
    "IceLakeX": "aes",
    "TigerLake": "aes",
    "SapphireRapids": "aes",
    "ADLpatch": "aes",
    "MTLpatchRSA": "aes",
    "GNRpatchRSA": "aes",
    "LNLMpatchRSA": "aes",
    "ARLpatchRSA": "aes",
    "PTLpatchRSA": "aes",
}

unix_proj_dict = {
    "skl": 'setSKLr -m ucode',
    "skl": 'setSKLr -m ucode',
    "CFL": 'setSKLr -m ucode',
    "KBL": 'setSKLr -m ucode',
    "CML": 'setCML -m ucode',
    "icl": 'setSNCd -m ucode',
    "icx": 'setSNCd -m ucode',
    "cnl": '',
    "skx": 'setSKLr -m ucode',
    "spr": 'setGLC -m ucode',
    "adl": 'setGLC -m ucode',
    "rkl": 'setCPCs',
    "rpl": 'setRPC',
    "mtl": 'setRWC -m ucode',
    "LNL": 'setLNC -m ucode',
    "ARLS": 'setLNC -m ucode',
    "PTL": 'setCGC -m ucode',
}

site_prefix_dict = {
    "iil": r'\\isamba.iil.intel.com',
    "sc": r'\\samba.sc.intel.com',
    "sc1": r'\\sc1-samba.sc.intel.com',
    "iil2": r'\\ismb013.iil.intel.com',
    "pdx": r'\\pdx-samba.sc.intel.com',
    "sc8": r'\\sc8-samba.sc.intel.com'
}

dualsign_XMSS = ['mtl', 'gnr', 'lnl', 'arls', 'arlh', 'ptl','wcl']

core_also_need_encryption_project = ['lnl', 'arls', 'arlh', 'ptl','wcl']

def main():
    # check the script is running on python 3. if not, die
    pyVersion = sys.version
    print(sys.version)
    if pyVersion[0] != '3':
        print("please run this script on python 3!")
        input("Hit any key to exit")
        exit(1)
    
    user_name = ""
    password = ""
    
    # try to read password from code.txt file:
    if os.path.exists("code.txt"):
        f = open("code.txt", 'r')
        css_password = f.readline().strip()
        user_name = f.readline().strip()
        f.close()
    else:
        print("INFO: no code.txt file was found.")
        print("INFO: for a faster work please create a 'code.txt' file with your workflow password")
        css_password = getpass.getpass("Please  enter your workflow password:\n")
    
    module1 = "EMRR_MCHECK"
    module2 = "PPPE1"
    patch = "core"
    
    while 1:
        folder_path = input("Please enter UNIX path to patch directory:\n")
        folder_path = folder_path.strip()
        if folder_path == '':
            input('No folder input for signing. exiting the script!')
            exit(0)
        
        unix_folder = folder_path

        # convert unix path to windows path
        folder_path = folder_path.replace('/','\\')
        site = "iil"
        if ":" in folder_path:
            site, folder_path = folder_path.split(":", 1)
        folder_prefix = site_prefix_dict[site]
        folder_path = folder_prefix + folder_path

        print("working on " + site + " site")
        print("Working folder:\n" + folder_path)

        # check if the folder exist:
        if not os.path.isdir(folder_path):
            signal_error("patch folder doesn't exist", folder_path)

        # get the name of the patch
        all_files = os.listdir(folder_path)
        patch_name = ""
        for file in all_files:
            if file.endswith(".patch"):
                patch_name = file.replace(".patch", "")
        if not patch_name:
            signal_error("could not find .patch in ", folder_path)

        # generate paths for encryption:
        m1_fp = os.path.join(folder_path,  patch_name + "_" + module1 + ".bin")
        m2_fp = os.path.join(folder_path,  patch_name + "_" + module2 + ".bin")
        patch_fp = os.path.join(folder_path,  patch_name + "_" + patch + ".bin")
        patch_fp_no_xucode = os.path.join(folder_path,  patch_name + ".bin")
        dot_patch_fp = os.path.join(folder_path,  patch_name + ".patch")
        m1_hash_fp = m1_fp.replace(".bin", "_encrypted_hash.bin")
        m2_hash_fp = m2_fp.replace(".bin", "_encrypted_hash.bin")
        # this will be needed only for projects that need to encrypt the core bin as well
        patch_enc_fp = patch_fp.replace(".bin", "_encrypted.bin")

        # enter to the code sign dir
        code_sign_path = os.getenv('APPDATA') + '\\CSS_HOME\\Intel\\LT CSS\\Bin'
        if not os.path.isdir(os.getenv('APPDATA') + '\\CSS_HOME\\Intel\\LT CSS\\Bin'):  # check if CSS exist on the system
            signal_error("no CSS installed on the system")
        
        os.chdir(code_sign_path)

        if not os.path.isfile(dot_patch_fp):
            dot_patch_fp = ""
            all_files = os.listdir(folder_path)
            for file in all_files:
                if file.endswith(".patch"):
                    dot_patch_fp = folder_path + "\\" + file
            # if we still didn't find any .patch file - error and exit:
            if not dot_patch_fp:
                signal_error("could not find", dot_patch_fp)

        # get target stepping, project and sign_id from patch_default.patch
        stepping = ""
        project = ""
        sign_id = ""
        algo = ""
        proj = ""

        patch_file = open(dot_patch_fp, 'r')
        while sign_id == "" or stepping == "" or project == "" or functionality == "":
            line = patch_file.readline()
            # import pdb;pdb.set_trace()
            if line.split('(')[0].strip() == "target_steppings":
                stepping = line.split('(')[1].split(')')[0]
            if line.split('(')[0].strip() == "project":
                project = line.split('(')[1].split(')')[0]
            if line.split('(')[0].strip() == "sign_id":
                sign_id = line.split('(')[1].split(')')[0]
            if line.split('(')[0].strip() == "functionality":
                functionality = line.split('(')[1].split(')')[0]
        patch_file.close()
        
        if functionality == "DEBUG":
            print("Running script for debug sign mode")
        else:
            print("Running script for encryption only (production mode)")
        print("stepping {0}\nproject {1}\nsign ID {2}".format(stepping, project, sign_id))
        
        if project in project_dict:
            proj = project_dict[project]

        if proj in algo_dict:
            algo = algo_dict[proj]

        if proj == "":
            print("Could not identify your project.")
            proj = input("Please enter the project's name (as it appears in the codeSign)")
        
        if algo == "":
            print("no algorithm is known for this project (usually, older are rc4 and newer are aes).")
            algo = input("Please enter the algorithm to sign (as it appears in the codeSign)")

        print("CSS project is", proj)
        print("Algorithm is: " + algo)
        
        # if (not os.path.isfile(dot_patch_fp)):
        #     signal_error("could not find" + dot_patch_fp)
        # check if need encryption.. if not sign only debug..	

        encyption_needed = True
        # encrypt the PPPE file if exist:
        if os.path.isfile(m1_fp):
            print("encrypting {0} module for {1}".format(module1, proj))
            full_command = "codesign.exe --emencrypt --project {0} --input {1} --hashfile" \
                           " {2} --algorithm {3} --password {4}".format(proj, m1_fp, m1_hash_fp, algo, css_password)
            command_result = ""
            try:
                command_result = check_output(full_command)
            except CalledProcessError as e:
                signal_error("Failed to sign {0}".format(module1), command_result + str(e.output))
            print("Finished Building {0}".format(module1))
        else:
            print("no ", module1, " exist, skipping encrypting it")
            encyption_needed = False

        # encrypt the EMRR file if exist:
        if os.path.isfile(m2_fp):
            print("encrypting {0} module for {1}".format(module2, proj))
            full_command = "codesign.exe --emencrypt --project {0} --input {1} --hashfile" \
                           " {2} --algorithm {3} --password {4}".format(proj, m2_fp, m2_hash_fp, algo, css_password)
        
            command_result = ""
            try:
                command_result = check_output(full_command)
            except CalledProcessError as e:
                signal_error("Failed to sign {0}".format(module2), command_result + str(e.output))
            print("Finished Building {0}".format(module2))
        else:
            print("no ", module2, " exist, skipping encrypting it")

        # if this is a project that needs also core encryption, encrypt it:
        if project in core_also_need_encryption_project:
            if os.path.isfile(patch_fp):
                print("encrypting {0} module for {1}".format(patch, proj))
                full_command = "codesign.exe --emencrypt --project {0} --input {1} --hashfile" \
                               " {2} --algorithm {3} --password {4}".format(proj, patch_fp, patch_enc_fp, algo,
                                                                            css_password)

                command_result = ""
                try:
                    command_result = check_output(full_command)
                except CalledProcessError as e:
                    signal_error("Failed to sign {0}".format(patch), command_result + str(e.output))
                print("Finished encrypting the core file (LNL forward) {0}".format(patch))
            else:
                signal_error("couldn't find the core path:", patch_fp)

            # from now on only work on the encrypted file instead of the unencrypted:
            patch_fp = patch_enc_fp


        if functionality == "PROD":
            print("finished encrypting the core")
            script_passed()
            continue
        
        # sign patch_default file if it's not a production patch
        print("debug signing the core")

        if not os.path.isfile(patch_fp):
            print("no core patch was found, trying the no-xucode patch")
            patch_fp = patch_fp_no_xucode

        command_result = ""
        if project in dualsign_XMSS:
            # assuming that project names for dual signing will be *RSA and *XMSS, so replacing RSA with XMSS will give the XMSS project
            proj_xmss = proj.replace('RSA','XMSS')
            full_command = "codesign.exe --dual-sign --debug --projects {0} {1} --input {2} --password {3}".\
            format(proj, proj_xmss, patch_fp, css_password)
        else:
            full_command = "codesign.exe --wfsign --debug --project {0} --input {1} --password {2}".\
                format(proj, patch_fp, css_password)
        try:
            command_result = check_output(full_command)
        except CalledProcessError as e:
            signal_error("Failed to sign core patch", command_result + str(e.output))

        if user_name == "":
            print("finished debug sign the core patch without merging.")
            script_passed()
            continue
        print('merging files in unix area.')
        try:
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect("idclogin6.iil.intel.com", username=user_name)
        except:
            print('unable to connect to unix. finishing without merging')
            script_passed()
            continue
        ssh_stdin, ssh_stdout, ssh_stderr = "", "", ""
        if not encyption_needed:
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('{setENV} ; cd {patch_dir} ; my_bios_patch'
                    .format(setENV=unix_proj_dict[project], patch_dir=unix_folder))
        elif project == 'spr' or project == 'adl':
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('{setENV} ; cd {patch_dir} ; $MODEL_ROOT/core/ucode/tools/src/ucode_utils/bin/merge_unipatch.pl -complete'
                    .format(setENV=unix_proj_dict[project], patch_dir=unix_folder))
        else:
            ssh_stdin, ssh_stdout, ssh_stderr = ssh.exec_command('ssh unix ; {setENV} ; cd {patch_dir} ; $PROJ_TOOLS/ucode_utils/latest/bin/merge_unipatch.pl -complete'
                    .format(setENV=unix_proj_dict[project], patch_dir=unix_folder))
        result = ssh_stdout.read().decode()
        ssh.close()
        result = result.split('\n')
        
        if encyption_needed and result[-2] != 'bios_patch: Success':
            print('merge result failed. please try to merger patch manually!')
            print('patch is still signed!')
        else:
            print('merge finished successfully!')
            print("finished debug sign the core patch.")
        script_passed()


if __name__ == "__main__":
    main()
