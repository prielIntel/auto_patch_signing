# patch-sign

automatic script to sign patches.


Put your linux patch path, it will convert automatically to access the linux from your computer.

put the site name with a colon as a prefix to the path in order to specify a specific site (default iil)

for example:
iil:/nfs/iil/proj/mpg/paharoni_wa1/sightings/cet_nmi_ist/adl_patch_cet_8010001C

The script parse the *.patch file in the area and extract the project from it,
encrypt the xucode files if needed (EMRR_MCHECK/PPPE) and sign the core_patch 
(or the non-uniform patch if xucode are missing).

feel free to add samba-path to the site.
feel free to adjust the script per need (just keep it documented).