"""
UCSTool v1.2
Created on 7-Aug-2020
Updated on 29-Jan-2025
@author: Akash(akmalla) ,Gayatri(gakumari) , Afroj(afrahmad) ,Nachiketa(nroutray) ,Kris(kvadecr)
"""
import warnings

warnings.filterwarnings("ignore")
import time
import datetime
import logging
import sys
import os
import json
import shutil
import re
import tarfile
import gzip
import urllib.request
from crank import search
from check_jumbo_mtu import check_jumbo_mtu, split_into_indented_blocks
from prettytable import PrettyTable, ALL
from progressbar import ProgressBarThread

########################       Logger        #################################
INFO = logging.INFO
DEBUG = logging.DEBUG
ERROR = logging.ERROR

# Global Variable
toolversion = 2.0
builddate = "2021-06-15"
usr_ch = ""


########################       Functions        #################################
def get_date_time():
    # Get Current Date & Time
    return (datetime.datetime.now().strftime("%Y-%m-%d_%I-%M-%S"))


def log_start(log_file, log_name, lvl):
    # Create a folder
    cdate = datetime.datetime.now()
    global dir_name
    dir_name = "UCS_Report_" + str(cdate.strftime("%Y_%m_%d_%H_%M_%S"))
    try:
        os.makedirs(dir_name)
    except FileExistsError:
        shutil.rmtree(dir_name)
        os.makedirs(dir_name)
    os.chdir(dir_name)
    # Configure logger file handler
    global logger
    log_level = lvl
    logger = logging.getLogger(log_name)
    logger.setLevel(log_level)

    # Create a file handler
    handler = logging.FileHandler(log_file)
    handler.setLevel(log_level)

    # Create a logging format
    formatter = logging.Formatter('%(asctime)s - %(name)s - %(levelname)s - %(message)s', '%Y-%m-%d %I:%M:%S')
    handler.setFormatter(formatter)

    # Add the handlers to the logger
    logger.addHandler(handler)
    msg = "UCS Health Check Tool Started at Date/Time :" + get_date_time().replace("_", "/")
    global start_time
    start_time = datetime.datetime.now()
    logger.info(msg)
    # log_msg("", msg)
    logger.info("Logger Initialized")


def log_stop():
    # Exit the logger and stop the script, used for traceback error handling
    log_msg(INFO, "Closing logger and exiting the application")
    msg = "UCS Health Check Tool Stopped at Date/Time :" + get_date_time().replace("_", "/")
    log_msg(INFO, msg)
    end_time = datetime.datetime.now()
    time_diff = end_time - start_time
    msg = "Test duration: " + str(time_diff.seconds) + " seconds"
    log_msg(INFO, msg)
    logging.shutdown()


def log_entry(cmd_name):
    # Each function will call this in the beginning to enter any DEBUG info
    logger.log(DEBUG, 'Entered command :' + cmd_name)


def log_exit(cmd_name):
    # Each function will call this in the end, to enter any DEBUG info
    logger.log(DEBUG, 'Exited command :' + cmd_name)


def log_msg(lvl, *msgs):
    # Each function will call this to enter any INFO msg
    msg = ""
    if len(msgs) > 1:
        for i in msgs:
            msg = msg + str(i) + "\n"
        msg.rstrip("\n")
    else:
        for i in msgs:
            msg = msg + str(i)
    # Print on Console & log
    for line in msg.split("\n"):
        if lvl == "" and line != "":
            print(line)
        elif line != "":
            logger.log(lvl, str(line))


def sys_exit(val):
    # End the script
    try:
        log_stop()
    except Exception:
        pass
    sys.exit(val)


def check(l):
    # ASCII Error handler
    return "".join(filter(lambda x: ord(x) < 128, l))


########################################################################

def extract_files(filePath):
    # Extract the tar file
    primaryFile = ""
    secondaryFile = ""
    tar = tarfile.open(filePath, 'r')
    # Check Primary
    for member in tar:
        if member.isfile():
            if member.name.endswith('.tar.gz'):
                subtar = tarfile.open(mode='r|gz', fileobj=tar.extractfile(member))
                for submember in subtar:
                    if "sam_techsupportinfo" in submember.name:
                        log_msg(INFO, "Got File: " + submember.name)
                        subtar.extract(submember, "./logFiles")
                        primaryFile = member.name
                        subtar.close()
                        break
    log_msg(INFO, "Primary File: " + primaryFile)
    # Get remaining file from Primary tar file
    if primaryFile:
        for member in tar:
            if member.isfile():
                if primaryFile in member.name and member.name.endswith('.tar.gz'):
                    subtar = tarfile.open(mode='r|gz', fileobj=tar.extractfile(member))
                    for submember in subtar:
                        # print(submember.name)
                        if "sw_techsupportinfo" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif "sam_cluster_state" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif "sam_process_state" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif "df_a.out" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif submember.name.endswith("var/sysmgr/sam_logs/svc_sam_dcosAG.log"):
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif submember.name.endswith("ls_l.out"):
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif submember.name.endswith("dmesg.out"):
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                        elif submember.name.endswith("mit.xml.gz"):
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")
                            try:
                                extract_mit_file()
                            except Exception:
                                pass
                        """
                        elif "smartctllog" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFiles")"""

                elif member.name.endswith('.tar.gz'):
                    secondaryFile = member.name
                    subtar = tarfile.open(mode='r|gz', fileobj=tar.extractfile(member))
                    for submember in subtar:
                        if "sw_techsupportinfo" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFilesB")
                        elif "sam_process_state" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFilesB")
                        elif "df_a.out" in submember.name:
                            log_msg(INFO, "Got File: " + submember.name)
                            subtar.extract(submember, "./logFilesB")
        tar.close()
        log_msg(INFO, "Secondary File: " + secondaryFile)
        return True
    else:
        tar.close()
        return False


def extract_mit_file():
    # Extract Mit.xml file
    mit = "./logFiles/mit.xml.gz"
    if os.path.isfile(mit):
        with gzip.open(mit, 'rb') as f_in:
            with open("./logFiles/mit.xml", 'wb') as f_out:
                shutil.copyfileobj(f_in, f_out)


def check_cluster_state():
    # Check Cluster State
    log_msg(INFO, "Check Cluster State")
    samCluster = "./logFiles/sam_cluster_state"
    clust = []
    cstate = ""
    c = 0
    flg1 = flg2 = flg3 = 0
    global primary, subordinate
    if os.path.isfile(samCluster):
        with open(samCluster, "r") as fh:
            for line in fh:
                # line = str(line.decode('ascii'))
                if "Cluster Id" in line:
                    c += 1
                    continue
                if c == 2:
                    if bool(re.match(r"(A|B)\: (UP|DOWN)", line)):
                        clust.append(line.strip())
                        if "UP" in line:
                            flg1 = 1
                            if "A:" in line and "PRIMARY" in line:
                                primary = "A"
                                subordinate = "B"
                            elif "B:" in line and "PRIMARY" in line:
                                primary = "B"
                                subordinate = "A"
                        continue
                    if "mgmt services state:" in line:
                        clust.append(line.strip())
                        if "UP" in line:
                            flg2 = 1
                        continue
                    if bool(re.match(r"^HA \w+", line)):
                        clust.append(line.strip())
                        if "HA READY" in line:
                            flg3 = 1
                        break
    if flg1 == 1 and flg2 == 1 and flg3 == 1:
        cstate = "PASS"
        detResult["UCSM HA Cluster State"] = {"Status": "\n".join(clust), "Result": cstate}
        sumResult["UCSM HA Cluster State"] = {"Status": cstate, "Result": ""}
    else:
        cstate = "FAIL"
        detResult["UCSM HA Cluster State"] = {"Status": "\n".join(clust), "Result": cstate}
        sumResult["UCSM HA Cluster State"] = {"Status": cstate, "Result": "Contact TAC"}


def check_process_state():
    # Check Process State
    log_msg(INFO, "Check Process State")
    samProcess = "./logFiles/sam_process_state"
    samProcessB = "./logFilesB/sam_process_state"
    state = "PASS"
    pstates = []
    if os.path.isfile(samProcess):
        pstates.append("Side " + primary + ":")
        with open(samProcess, "r") as fh:
            for line in fh:
                pstates.append(line.strip())
                if "failed" in line:
                    state = "FAIL"
    if os.path.isfile(samProcessB):
        pstates.append("\nSide " + subordinate + ":")
        with open(samProcessB, "r") as fh:
            for line in fh:
                pstates.append(line.strip())
                if "failed" in line:
                    state = "FAIL"
    if state == "PASS":
        detResult["PMON Process State"] = {"Status": "\n".join(pstates), "Result": state}
        sumResult["PMON Process State"] = {"Status": state, "Result": ""}
    else:
        detResult["PMON Process State"] = {"Status": "\n".join(pstates), "Result": state}
        sumResult["PMON Process State"] = {"Status": state, "Result": "Contact TAC"}


def check_file_system():
    # Check File System Mount
    log_msg(INFO, "Check File System Mount")
    dfOut = "./logFiles/df_a.out"
    dfOutB = "./logFilesB/df_a.out"
    dflag = 0
    mount = []
    sysmgrCheck = False
    sysmgrSize = ""
    tmpCheck = False
    tmpSize = ""
    if os.path.isfile(dfOut):
        mount.append("Side " + primary + ":")
        with open(dfOut, "r") as fh:
            for line in fh:
                if "Filesystem" in line:
                    mount.append(line.strip())
                    mount.append("----------           ---------      ---- --------- ---  ----------")
                    continue
                elif bool(re.match(r"\/dev\/sda[3-9] ", line)):
                    dflag = 1
                    mount.append(line.strip())
                elif line.strip().endswith("/var/sysmgr"):
                    # /var/sysmgr directory usage >80%
                    m1 = re.search(r".*(8[1-9]|9[0-9]|100)%.*\/var\/sysmgr", line)
                    if m1:
                        sysmgrCheck = True
                        sysmgrSize = line.strip()
                elif line.strip().endswith("/var/tmp"):
                    # /var/tmp/ directory usage >=10%
                    m2 = re.search(r"(\d+)\%.*\/var\/tmp", line)
                    if m2:
                        used_space = m2.group(1)
                        if int(used_space) > 10:
                            tmpCheck = True
                            tmpSize = line.strip()

    if os.path.isfile(dfOutB):
        mount.append("\nSide " + subordinate + ":")
        with open(dfOutB, "r") as fh:
            for line in fh:
                if "Filesystem" in line:
                    mount.append(line.strip())
                    mount.append("----------           ---------      ---- --------- ---  ----------")
                    continue
                if bool(re.match(r"\/dev\/sda[3-9] ", line)):
                    dflag = 1
                    mount.append(line.strip())

    if dflag:
        sumResult["File System Mount"] = "PASS"
        detResult["File System Mount"] = {"Status": "\n".join(mount), "Result": "PASS"}
    else:
        sumResult["File System Mount"] = {"Status": "FAIL", "Result": "Contact TAC"}
        detResult["File System Mount"] = {"Status": "\n".join(mount), "Result": "FAIL"}

    # Check for /var/sysmgr size issue
    # UCS_BORG_Check_for_CSCut28278
    if sysmgrCheck:
        sumResult["Check for /var/sysmgr size issue"] = {"Status": "Found", "Result": "1.Check the FI disk space usage using below command on both FI\n#connect nxos a\n#show system internal flash\n2.delete old core dump files\nAfter recovering disk space, restart pmon from local-mgmt CLI context"}
        detResult["Check for /var/sysmgr size issue"] = {"Status": "/var/sysmgr directory usage exceeds 80%." + "\n" + sysmgrSize,
                                                         "Result": "Found"}
    else:
        sumResult["Check for /var/sysmgr size issue"] = {"Status": "Not Found", "Result": ""}
        detResult["Check for /var/sysmgr size issue"] = "Not Found"

    # Check for /var/tmp size issue
    # UCS_BORG_var_tmp_CSCuv03557
    if tmpCheck:
        sumResult["Check for /var/tmp size issue"] = {"Status": "Found", "Result": "1.Check the FI disk space usage using below command on both FI\n#connect nxos a\n#show system internal flash\n2.Delete old files\nAfter recovering disk space, restart pmon from local-mgmt CLI context"}
        detResult["Check for /var/tmp size issue"] = {"Status": "/var/tmp directory usage exceeds 80%." + "\n" + tmpSize,
                                                      "Result": "Found"}
    else:
        sumResult["Check for /var/tmp size issue"] = {"Status": "Not Found", "Result": ""}
        detResult["Check for /var/tmp size issue"] = "Not Found"


def check_fi_version():
    # Check FI Version
    log_msg(INFO, "Check FI Version")
    swTech = "./logFiles/sw_techsupportinfo"
    swTechB = "./logFilesB/sw_techsupportinfo"
    global safeshutCheck, fiTrdGenCheck
    fiv = []
    flg1 = flg2 = 0
    md1 = md2 = ""
    hflag1 = hflag2 = hflag3 = hflag4 = 0
    fiUnresponsiveCheck = False
    fiUnresponsive = ""
    if os.path.isfile(swTech):
        fiv.append("Side " + primary + ":")
        with open(swTech, "r", encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if "show module" in line:
                    flg1 = 1
                    continue
                elif flg1 == 1 and "MAC-Address" in line:
                    break
                elif flg1 == 1:
                    fiv.append(line.strip())
                    if "UCS-FI-6296" in line:
                        md1 = line.strip().split()[0]
                        hflag1 = 1
                    if "UCS-FI-63" in line:
                        fiTrdGenCheck = True
                    if hflag1 == 1 and line.startswith(md1):
                        hw = line.strip().split()
                        hw = [x for x in hw if x != ""]
                        hw = hw[2]
                        if hw == "1.0":
                            hflag2 = 1
                    elif hflag1 == 1 and re.search("1\s+.*\s+1.0", line):
                        # Confirm the first module, the FI, is running HW version 1.0
                        fiUnresponsiveCheck = True
                        fiUnresponsive = line.strip()
                    if "active" in line and ("UCS-FI-6248" in line or "UCS-FI-6296" in line):
                        safeshutCheck = True

    if os.path.isfile(swTechB):
        fiv.append("\nSide " + subordinate + ":")
        with open(swTechB, "r", encoding='utf-8', errors='ignore') as fh:
            for line in fh:
                if "show module" in line:
                    flg2 = 1
                    continue
                elif flg2 == 1 and "MAC-Address" in line:
                    break
                elif flg2 == 1:
                    fiv.append(line.strip())
                    if "UCS-FI-6296" in line:
                        md2 = line.strip().split()[0]
                        hflag3 = 1
                    if hflag3 == 1 and line.startswith(md2):
                        hw = line.strip().split()
                        hw = [x for x in hw if x != ""]
                        hw = hw[2]
                        if hw == "1.0":
                            hflag4 = 1

    # DS_UCS_CSCun00720_FI_6296_FI
    # 6296 FI unresponsive after power cycle, HW revision update
    if fiUnresponsiveCheck:
        sumResult["6296 FI unresponsive after power cycle, HW revision update"] = {"Status": "Found", "Result": "Contact TAC"}
        detResult["6296 FI unresponsive after power cycle, HW revision update"] = {"Status": fiUnresponsive, "Result": "Found"}
    else:
        sumResult["6296 FI unresponsive after power cycle, HW revision update"] = {"Status": "Not Found", "Result": ""}
        detResult["6296 FI unresponsive after power cycle, HW revision update"] = "Not Found"


def check_sam_tech():
    # Check Sam_techsupportinfo file
    samTech = "./logFiles/sam_techsupportinfo"
    global majorFault, criticalFault, ucsVersion, fiVersion, safeshutCheck, bootflashCheck, tarVersion, upgradePath, usr_ch
    if os.path.isfile(samTech):
        # Check Faults with Severity Major and Critical
        log_msg(INFO, "Check Faults with Severity Major and Critical")
        flag = mflag = cflag = 0
        code = ""
        with open(samTech, "r") as fh:
            for line in fh:
                if "show fault detail" in line:
                    flag = 1
                    continue
                elif flag == 1 and "Fault Instance" in line:
                    continue
                elif flag == 1 and "`scope fault policy`" in line:
                    break
                elif flag == 1 and line.startswith("Severity:") and "Major" in line:
                    mflag = 1
                    continue
                elif flag == 1 and line.startswith("Severity:") and "Critical" in line:
                    cflag = 1
                    continue
                elif mflag == 1 and "Code:" in line:
                    code = ""
                    if len(line.strip().split("Code:")) == 2:
                        code = line.strip().split("Code:")[1].strip()
                    if "F1219" in line:
                        bootflashCheck = True
                    continue
                elif mflag == 1 and "Description:" in line:
                    decr = ""
                    if len(line.strip().split("Description:")) == 2:
                        decr = line.strip().split("Description:")[1].strip()
                    majorFault.append(code + ": " + decr)
                    mflag = 0
                    continue
                elif cflag == 1 and "Code:" in line:
                    code = ""
                    if len(line.strip().split("Code:")) == 2:
                        code = line.strip().split("Code:")[1].strip()
                    if "F1219" in line:
                        bootflashCheck = True
                    continue
                elif cflag == 1 and "Description:" in line:
                    decr = ""
                    if len(line.strip().split("Description:")) == 2:
                        decr = line.strip().split("Description:")[1].strip()
                    criticalFault.append(code + ": " + decr)
                    cflag = 0
                    continue
        if majorFault or criticalFault:
            sumResult["Faults with Severity Major or Severity Critical"] = {"Status": "Found", "Result": "Review the faults and Contact TAC, if needed"}
        else:
            sumResult["Faults with Severity Major or Severity Critical"] = {"Status": "Not Found", "Result": ""}

        # Get UCS Version
        log_msg(INFO, "Get UCS Version")
        flag1 = flag2 = flag3 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show firmware`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "Package-Vers:" in line:
                    try:
                        ucsVersion = line.strip().split(": ")[1]
                        break
                    except Exception:
                        pass
                elif flag1 == 1 and "Running-Vers:" in line and not ucsVersion:
                    try:
                        ucsVersion = line.strip().split(": ")[1]
                        break
                    except Exception:
                        flag2 = 1
                elif flag2 == 1 and "`show system firmware expand detail`" in line:
                    flag3 = 1
                    continue
                elif flag3 == 1 and "Running-Vers:" in line:
                    try:
                        ucsVersion = line.strip().split(": ")[1]
                        break
                    except Exception:
                        break
        log_msg(INFO, "UCSM Version: " + ucsVersion)
        log_msg("", "UCSM Version: " + ucsVersion)
        print("")
        if usr_ch.lower() == "2":
            log_msg(INFO, "Target Version: " + tarVersion)
            log_msg("", "Target Version: " + tarVersion)
            uPath = check_upgrade_path(ucsVersion, tarVersion)
            log_msg(INFO, "Upgrade Path: " + str(upgradePath))
            print("")
            if type(uPath) == str:
                upgradePath = uPath
                log_msg("", "Upgrade Path: " + upgradePath)
            else:
                upgradePath = "NA"
                log_msg("", "Upgrade Path: " + upgradePath)

        # Get FI version
        log_msg(INFO, "Get FI Version")
        flag1 = flag2 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show firmware monitor`" in line:
                    flag1 = 1
                    continue
                elif flag2 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and ("Fabric Interconnect A:" in line or "Fabric Interconnect B:" in line):
                    flag2 = 1
                elif flag2 == 1 and "Package-Vers:" in line:
                    try:
                        fiVersion = line.strip().split(": ")[1]
                        break
                    except Exception:
                        pass
                elif flag2 == 1 and "Running-Vers:" in line and not fiVersion:
                    try:
                        fiVersion = line.strip().split(": ")[1]
                        break
                    except Exception:
                        pass
        log_msg(INFO, "FI Version: " + fiVersion)

        # Check Audit Logs for Backup Available
        log_msg(INFO, "Check Audit Logs for Backup Available")
        backup = 0
        flag = 0
        # with open(samTech, "r") as fh:
        #     for line in fh:
        #         if "`show audit-logs detail`" in line:
        #             flag = 1
        #             continue
        #         elif flag == 1 and "`show " in line:
        #             break
        #         elif flag == 1 and "Description: Backup task for admin" in line:
        #             backup = 1
        with open(samTech, "r") as fh:
            for line in fh:
                if 'enter backup :' in line:
                    backup = 1
                    break
        if backup:
            sumResult["Check Backup Available"] = {"Status": "Found", "Result":"Backup operation has been found. However, please ensure that the latest backup is captured as a best practice."}
            detResult["Check Backup Available"] = {"Status": "Backup Operation Found", "Result":"Found"}
        else:
            sumResult["Check Backup Available"] = {"Status": "Backup Operation Not Found", "Result": "Backup operation has not been found. Please ensure that the latest backup is captured as a best practice."}
            detResult["Check Backup Available"] = {"Status": "", "Result": "Backup Operation Not Found"}
        

        # Check Keyring modulus size
        log_msg(INFO, "Check Keyring modulus size")
        keySize = ""
        keyStatus = ""
        keyringExpiry = False
        regenerateKeyring = False
        flag1 = flag2 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show keyring`" in line and "detail" not in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and "Name" in line:
                    continue
                elif flag1 == 1 and "-----------" in line:
                    continue
                else:
                    m = re.search(r"mod(\d+)", line.strip(), re.IGNORECASE)
                    if m:
                        keySize = m.group(1)
        log_msg(INFO, "Keyring Size: " + keySize)
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show keyring detail`" in line:
                    flag2 = 1
                    continue
                elif flag2 == 1 and "`show " in line:
                    break
                elif flag2 == 1 and "Cert Status:" in line:
                    try:
                        keyStatus = line.strip().split(": ")[1]
                    except Exception:
                        pass
                    break
        log_msg(INFO, "Keyring Status: " + keyStatus)
        if "expired" in keyStatus.lower():
            keyringExpiry = True
        if not keyringExpiry and float(ucsVersion[:3]) < 3.1:
            if keySize:
                if int(keySize) < 2048:
                    regenerateKeyring = True
        status = "Keyring Size: " + keySize + "\nKeyring Cert Status: " + keyStatus
        if keyringExpiry:
            sumResult["Keyring Cert Check"] = {"Status": "FAIL", "Result": "To regenerate the certificate, please SSH to the UCS Manager CLI (primary / VIP) and run the following commands:\nUCS-Primary # scope security\nUCS-Primary /security # scope keyring default\nUCS-Primary /security/keyring # set regenerate yes\nUCS-Primary /security/keyring # set modulus mod2048\nUCS-Primary /security/keyring* # commit-buffer\nOnce you enter the 'commit-buffer' , UCSM GUI will be disconnected for a while.\nLogin after few mins to verify the Cert status."}
            detResult["Keyring Cert Check"] = {"Status": status, "Result": "FAIL"}
        elif regenerateKeyring:
            sumResult["Keyring Cert Check"] = {"Status": "FAIL", "Result": "To regenerate the certificate, please SSH to the UCS Manager CLI (primary / VIP) and run the following commands:\nUCS-Primary # scope security\nUCS-Primary /security # scope keyring default\nUCS-Primary /security/keyring # set regenerate yes\nUCS-Primary /security/keyring # set modulus mod2048\nUCS-Primary /security/keyring* # commit-buffer\nOnce you enter the 'commit-buffer' , UCSM GUI will be disconnected for a while.\nLogin after few mins to verify the Cert status."}
            detResult["Keyring Cert Check"] = {"Status": status, "Result": "FAIL"}
        else:
            sumResult["Keyring Cert Check"] = {"Status": "PASS", "Result": ""}
            detResult["Keyring Cert Check"] = {"Status": status, "Result": "PASS"}

        # Safeshut workaround needed or not
        log_msg(INFO, "Check Safeshut workaround needed or not")
        if float(fiVersion.strip()[:3]) < 2.2:
            sumResult["Safeshut Workaround Needed or Not"] = {"Status": "Not Needed", "Result": ""}
            detResult["Safeshut Workaround Needed or Not"] = "Not Needed"
        elif float(fiVersion.strip()[:3]) > 2.2 and safeshutCheck == 1:
            sumResult["Safeshut Workaround Needed or Not"] = {"Status": "Not Needed", "Result": ""}
            detResult["Safeshut Workaround Needed or Not"] = "Not Needed"
        elif float(fiVersion.strip()[:3]) == 2.2 and safeshutCheck == 1:
            if str(fiVersion[4:6]) < "6c":
                sumResult["Safeshut Workaround Needed or Not"] = {"Status": "Needed", "Result": "Contact TAC"}
                detResult["Safeshut Workaround Needed or Not"] = {"Status": "Needed", "Result": "Contact TAC"}
            else:
                sumResult["Safeshut Workaround Needed or Not"] = {"Status": "Not Needed", "Result": ""}
                detResult["Safeshut Workaround Needed or Not"] = "Not Needed"
        else:
            sumResult["Safeshut Workaround Needed or Not"] = {"Status": "Not Needed", "Result": ""}
            detResult["Safeshut Workaround Needed or Not"] = "Not Needed"

        # Deprecated Hardware in Cisco UCS Manager Release 4.x
        log_msg(INFO, "Deprecated Hardware in Cisco UCS Manager Release 4.x")
        deviceList = []
        flag1 = flag2 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show server inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and line.startswith("Server "):
                    flag2 = 1
                elif flag2 == 1 and ("Equipped Product Name:" in line or "Acknowledged Product Name:" in line):
                    flag2 = 0
                    try:
                        device = line.strip().split(": ")[1]
                        m = re.search(r"Cisco\s+UCS\s+B\d+\s+M2", device)
                        if m:
                            deviceList.append(device)
                    except Exception:
                        pass
        if deviceList:
            sumResult["Deprecated Hardware in Cisco UCS Manager Release 4.x"] = {"Status": "Found", "Result": "Review the release notes to verify the hardware compatibility.\nRefer this link: \nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/CiscoUCSManager-RN-4-0.html"}
            detResult["Deprecated Hardware in Cisco UCS Manager Release 4.x"] = {"Status": "\n".join(deviceList), "Result": "Found"}
        else:
            sumResult["Deprecated Hardware in Cisco UCS Manager Release 4.x"] = "Not Found"
            detResult["Deprecated Hardware in Cisco UCS Manager Release 4.x"] = "Not Found"


def check_known_issues():
    # Check Known Issues
    samTech = r"./logFiles/sam_techsupportinfo"
    global ucsVersion, fiVersion, bootflashCheck, fiTrdGenCheck
    deprecatedPids = ['N10-S6100', 'N10-S6200', 'N20-I6584', 'N20-B6620-1', 'N20-B6620-2', 'N20-B6730-1', 'N20-B6740-2',
                      'N20-AE0002', 'N20-AQ0002', 'N20-AI0002', 'N20-AC0002', 'N20-AB0002', 'N20-AQ0102', 'N20-AE0102',
                      'R210-2121605W', 'UCSC-BASE-M2-C460', 'UCSC-BSE-SFF-C200', 'R250-2480805W', 'C260-BASE-2646',
                      'N20-AI0102', 'N2XX-ABPCI02', 'N2XX-ACPCI01', 'N2XX-AEPCI01', 'N2XX-AQPCI01', 'UCSB-MEZ-ELX-03',
                      'UCSB-MEZ-QLG-03', 'N20-B6625-2']
    if os.path.isfile(samTech):
        # UCS_BORG_Granada_Hardware
        # Deprecated HW found for 3.1.x onwards
        log_msg(INFO, "Check deprecated HW found for 3.1.x onwards")
        pidList = []
        # Check in server inventory
        flag1 = flag2 = flag3 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show server inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and line.startswith("Server "):
                    flag2 = 1
                elif flag2 == 1 and ("Equipped PID:" in line or "Acknowledged PID:" in line):
                    flag2 = 0
                    flag3 = 1
                    try:
                        pid = line.strip().split(": ")[1]
                        if pid in deprecatedPids:
                            pidList.append(pid)
                    except Exception:
                        pass
                elif flag3 == 1 and "MLOM" in line or "N20-A" in line or "UCS-VIC-" in line or "UCSB-MEZ" in line:
                    m = re.search(r"^ *\d ([^\s]*).*$", line)
                    if m:
                        pid = m.group(1)
                        if pid in deprecatedPids:
                            pidList.append(pid)
        # Check in show fabric-interconnect inventory expand
        flag1 = flag2 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show fabric-interconnect inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and (line.startswith("A:") or line.startswith("B:")):
                    flag2 = 1
                elif flag2 == 1 and ("UCS-FI" in line or "N10-S6" in line):
                    m = re.search(r"^.*((UCS-FI|N10-S6)[A-Z0-9-]*).*$", line)
                    if m:
                        pid = m.group(1)
                        if pid in deprecatedPids:
                            pidList.append(pid)
        # Check in show chassis iom detail
        flag1 = 0
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show chassis iom detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 == 1 and "PID: " in line:
                    m = re.search(r"^PID: ([A-Z0-9-]*)$", line)
                    if m:
                        pid = m.group(1)
                        if pid in deprecatedPids:
                            pidList.append(pid)
        if pidList:
            sumResult["Deprecated HW found for 3.1.x onwards"] = {"Status": "Found", "Result": "Review the release notes to verify the hardware compatibility.\nRefer these links:\nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/CiscoUCSManager-RN-3-1.html\nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/release/notes/CiscoUCSManager-RN-3-2.html"}
            detResult["Deprecated HW found for 3.1.x onwards"] = {"Status": "\n".join(pidList), "Result": "Found"}
        else:
            sumResult["Deprecated HW found for 3.1.x onwards"] = "Not Found"
            detResult["Deprecated HW found for 3.1.x onwards"] = "Not Found"

        # Check for B200M4 reboot due to blank MRAID12G fields
        # UCS_BORG_Check_CSCut61527
        # CSCut61527: B200 M4 reboot due to blank MRAID12G Serial number
        # CSCus42584: B200 M4 reboot due to missing UCSB-MRAID12G Vendor/Model attribute
        log_msg(INFO, "Check for B200M4 reboot due to blank MRAID12G fields")
        found_CSCut61527 = False
        found_CSCus42584 = False
        snBug = []
        mdBug = []
        flag1 = flag2 = flag3 = 0
        con1 = con2 = con3 = con4 = 0
        ser = raid = vendor = model = ""
        with open(samTech, "r") as fh:
            for line in fh:
                if "`show server inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 and line.startswith("`show "):
                    break
                elif flag1 and line.startswith("Server "):
                    flag2 = 1
                    ser = line.strip()
                    con1 = con2 = con3 = con4 = 0
                    vendor = model = ""
                    continue
                elif flag1 and flag2 and flag3 == 0 and ("Acknowledged PID:" in line or "Equipped PID:" in line):
                    if "B200-M4" in line:
                        con1 = 1
                elif flag1 and flag2 and "Adapter:" in line:
                    flag2 = flag3 = 0
                    continue
                elif flag1 and flag2 and re.search("(RAID Controller \d+):", line):
                    flag3 = 1
                    raid = line.strip()
                elif flag1 and flag2 and flag3 and "Vendor:" in line:
                    vendor = line.strip()
                    if con1 and not (line.strip().split("Vendor:")[1]):
                        con3 = 1
                elif flag1 and flag2 and flag3 and "Model:" in line:
                    model = line.strip()
                    if con1 and "UCSB-MRAID12G" in line:
                        con2 = 1
                    if con1 and not (line.strip().split("Model:")[1]):
                        con4 = 1
                elif flag1 and flag2 and flag3 and "Serial:" in line:
                    if con1 and con2 and not (line.strip().split("Serial:")[1]):
                        found_CSCut61527 = True
                        snBug.append(ser)
                        snBug.append(raid)
                        snBug.append(vendor)
                        snBug.append(model)
                        snBug.append(
                            line.strip() + "        <------ Serial Number is missing or incomplete (CSCut61527)\n")
                    if con1 and con3 and con4 and line.strip().split("Serial:")[1] and line.strip().split("Serial:")[
                        1] != "Unknown":
                        found_CSCus42584 = True
                        mdBug.append(ser)
                        mdBug.append(raid)
                        mdBug.append(
                            vendor + "        <------- Vendor information is missing or incomplete (CSCus42584)")
                        mdBug.append(model + "         <------- Model information is missing or incomplete (CSCus42584)")
                        mdBug.append(line)
                    elif con1 and not con3 and con4 and line.strip().split("Serial:")[1] and line.strip().split("Serial:")[1] != "Unknown":
                        found_CSCus42584 = True
                        mdBug.append(ser)
                        mdBug.append(raid)
                        mdBug.append(vendor)
                        mdBug.append(model + "        <------- Model information is missing or incomplete (CSCus42584)")
                        mdBug.append(line)
                    elif con1 and con3 and not con4 and line.strip().split("Serial:")[1] and line.strip().split("Serial:")[1] != "Unknown":
                        found_CSCus42584 = True
                        mdBug.append(ser)
                        mdBug.append(raid)
                        mdBug.append(
                            vendor + "        <------- Vendor information is missing or incomplete (CSCus42584)")
                        mdBug.append(model)
                        mdBug.append(line)
        if found_CSCus42584 and found_CSCut61527:
            sumResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "Found", "Result": "Contact TAC"}
            detResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": ("\n".join(mdBug)) + ("\n".join(snBug)), "Result": "Found"}
        elif found_CSCus42584 and not found_CSCut61527:
            sumResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "Found", "Result": "Contact TAC"}
            detResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "\n".join(mdBug), "Result": "Found"}
        elif not found_CSCus42584 and found_CSCut61527:
            sumResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "Found", "Result": "Contact TAC"}
            detResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "\n".join(snBug), "Result": "Found"}
        else:
            sumResult["Check for B200M4 reboot due to blank MRAID12G fields"] = {"Status": "Not Found", "Result": ""}
            detResult["Check for B200M4 reboot due to blank MRAID12G fields"] = "Not Found"

        # UCSM 3.1 Change in max power allocation causes blade discovery failure
        # DS_UCS_CSCuy52691_UCSM_31_Change
        log_msg(INFO, "Check UCSM 3.1 Change in max power allocation causes blade discovery failure")
        con1 = con2 = con3 = con4 = con5 = 0
        fault = []
        # Check UCSM version >= 3.1.1e
        if "3.1.1e" in ucsVersion or "3.1(1e)" in ucsVersion or float(ucsVersion[:3]) >= 3.1:
            flag1 = 0
            with open(samTech, "r") as f:
                for line in f:
                    if "show fault detail" in line:
                        flag1 = 1
                        continue
                    elif flag1 == 1 and "Fault Instance" in line:
                        continue
                    elif flag1 == 1 and "`scope fault policy`" in line:
                        break
                    elif flag1 == 1 and "Description:" in line:
                        if "Insufficient power available to power-on server" in line or "Check if power can be allocated to server" in line:
                            con1 = 1
                            fault.append(line)
                            break
            if con1:
                # Check for Grid PSU policy
                flag1 = 0
                with open(samTech, "r") as f:
                    for line in f:
                        if "`show psu-policy detail`" in line:
                            flag1 = 1
                            continue
                        elif flag1 and "`show" in line:
                            break
                        elif flag1 and "Redundancy:" in line:
                            if "Grid" in line:
                                con2 = 1
                                fault.append(line)
                                break
            if con2:
                # Default power cap policy
                flag1 = 0
                with open(samTech, "r") as f:
                    for line in f:
                        if re.match("`show service-profile.*detail expand`", line):
                            flag1 = 1
                            continue
                        elif flag1 and "`show" in line:
                            break
                        if flag1 and "Power Policy: no-cap" in line:
                            con3 = 1
                            fault.append(line)
                            break
            if con3:
                # Check available PSU power of chassis with Grid Policy
                flag1 = 0
                with open(samTech, "r") as f:
                    for line in f:
                        if "`show chassis detail`" in line:
                            flag1 = 1
                            continue
                        elif flag1 and "`show" in line:
                            break
                        elif flag1 and re.search("(PSU Capacity \(W\):\s5000)", line):
                            con4 = 1
                            fault.append(line)
                            break
            if con4:
                # Check default power control policy no-cap
                mitXml = r"./logFiles/mit.xml"
                if os.path.isfile(mitXml):
                    with open(mitXml, "r") as f:
                        for line in f:
                            if "defaultPolicyName=\"default\" dn=\"policy-ep/scope-cont-managed-endpoint/context-org-root/scope-powerPolicy-name-no-cap\"" in line:
                                con5 = 1
                                break
        if con5:
            sumResult["UCSM 3.1 Change in max power allocation causes blade discovery failure"] = {"Status": "Found", "Result": "Change the power control policy in Service Profile to \"cap \" with default priority value of \"5\".\nPlease plan to upgrade to one of latest release for permanent fix.\nRefer this link :\nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/ucs-manager/GUI-User-Guides/Server-Mgmt/3-1/b_Cisco_UCS_Manager_Server_Mgmt_Guide_3_1/power_management_for_blades_and_power_capping.html#concept_395A0C9B2CA746F1B4DA471E6CA6AD72"}
            detResult["UCSM 3.1 Change in max power allocation causes blade discovery failure"] = {"Status": "\n".join(fault), "Result": "Found"}
        else:
            sumResult["UCSM 3.1 Change in max power allocation causes blade discovery failure"] = {"Status": "Not Found", "Result": ""}
            detResult["UCSM 3.1 Change in max power allocation causes blade discovery failure"] = "Not Found"

    if bootflashCheck:
        log_msg(INFO, "Check existence of bootflash corruption fault code F1219")
        docsAG = r"./logFiles/var/sysmgr/sam_logs/svc_sam_dcosAG.log"
        agLog = []
        if os.path.isfile(docsAG):
            # Check existence of bootflash corruption fault code F1219
            # CSCuy85027
            with open(docsAG, "r") as fh:
                flg1 = flg2 = flg3 = 0
                k = ["bootflash", "opt", "workspace", "spare"]
                n = []
                l1 = l2 = l3 = ""
                for line in fh:
                    if "Executing /bin/sh command" in line:
                        l1 = line.strip()
                        flg1 = 1
                    if flg1 == 1 and "argv[1] = -c" in line:
                        l2 = line.strip()
                        flg2 = 1
                    if flg2 == 1 and "not clean" in line:
                        l3 = line.strip()
                        flg3 = 1
                    if flg1 == 1 and flg2 == 1 and flg3 == 1:
                        for i in k:
                            if i in l3 and i not in n:
                                agLog.append(l1 + '\n' + l2 + '\n' + l3 + '\n')
                                n.append(i)
                    if len(n) == len(k):
                        break
        if agLog:
            agLog.insert(0, "svc_sam_dcosAG.log file info:")
        sumResult["Existence of bootflash corruption fault code F1219"] = {"Status": "Found", "Result": "Contact TAC"}
        detResult["Existence of bootflash corruption fault code F1219"] = {"Status": "\n".join(agLog), "Result": "Found"}
    else:
        sumResult["Existence of bootflash corruption fault code F1219"] = {"Status": "Not Found", "Result": ""}
        detResult["Existence of bootflash corruption fault code F1219"] = "Not Found"

    # Check for httpd fail to start when default keyring is deleted
    # DS_UCS_CSCva67159_UCSM_httpd_fails
    log_msg(INFO, "Check for httpd fail to start when default keyring is deleted")
    lsOut = "./logFiles/ls_l.out"
    con1 = con2 = 0
    dCert = ""
    if os.path.isfile(lsOut):
        with open(lsOut, "r") as fh:
            for line in fh:
                if re.search("server\.crt.*\/default\.crt", line):
                    con1 = 1
                    dCert = line.strip()
                if re.search("[ \t][ \t]*default\.crt", line):
                    con2 = 1
                if con1 and con2:
                    break
    if con1 and not con2:
        sumResult["Check for httpd fail to start when default keyring is deleted"] = {"Status": "Found", "Result": "To regenerate the certificate, please SSH to the UCS Manager CLI (primary / VIP) and run the following commands:\nUCS # scope security\nUCS /security # create keyring default\nUCS /security/keyring* # set modulus mod2048\nUCS /security/keyring* # commit-buffer\nUCS /security/keyring # top\nNext , disable and enable the http/https service by running the below command:\nUCS # scope system\nUCS /system # scope services\nUCS /system/services #  disable https\nUCS /system/services* # disable http\nUCS /system/services* # commit-buffer\nUCS /system/services #  enable http\nUCS /system/services* #  enable https\nUCS /system/services* # commit-buffer\nPlease contact TAC to configure HTTPD to use customer ( third party ) certificate"}
        detResult["Check for httpd fail to start when default keyring is deleted"] = {"Status": dCert, "Result": "Found"}
    else:
        sumResult["Check for httpd fail to start when default keyring is deleted"] = {"Status": "Not Found", "Result": ""}
        detResult["Check for httpd fail to start when default keyring is deleted"] = "Not Found"

    # 3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"
    # CSCvi96785
    log_msg(INFO, 'Check 3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"')
    dmOut = r"./logFiles/dmesg.out"
    fcon = 0
    fst = []
    if fiTrdGenCheck and re.search(r"3\.0|3\.1\([1-2]|3\.1\(3[a-i]|3\.2\([1-2]|3\.2\(3[a-f]", fiVersion):
        if os.path.isfile(dmOut):
            with open(dmOut, "r") as fh:
                for line in fh:
                    if "EXT3-fs warning: mounting fs with errors, running e2fsck is recommended" in line:
                        fcon = 1
                        fst.append(line.strip())
                        break
    if fst:
        fst.insert(0, "dmesg.out file info:")
    if fcon:
        sumResult['3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"'] = {"Status": "Found", "Result": "If you are on 4.1.2 code or later then run the below command to clear the error:\nFI# connect local-mgmt\nFI(local-mgmt)# reboot e2fsck\nNote : Fault may take up to 72 hours to clear."}
        detResult['3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"'] = {"Status": "\n".join(fst), "Result": "Found"}
    else:
        sumResult['3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"'] = {"Status": "Not Found", "Result": ""}
        detResult['3rd GEN FIs has unclean file system states-"Filesystem state: clean with errors"'] = "Not Found"


def new_mu_checks():
    # New MU Checks
    # Server Auto-Install to 4.0(4b) or higher Fails to Activate SAS Controller
    # CSCvq53066
    log_msg(INFO, "Check server Auto-Install to 4.0(4b) or higher Fails to Activate SAS Controller")
    samTech = r"./logFiles/sam_techsupportinfo"
    found_CSCvq53066 = False
    global ucsVersion, fiVersion, bootflashCheck, fiTrdGenCheck, tarVersion
    if os.path.isfile(samTech):
        det_CSCvq53066 = []
        con1 = con2 = con3 = con4 = 0
        # check UCSM ver > 4.0(4b)
        if ucsVersion:
            ver_chk = ucsVersion.split("(")
            if float(ver_chk[0]) > 4.0:
                con4 = 1
            elif ver_chk[0] == '4.0':
                if ver_chk[1].split(")")[0].strip() >= '4b':
                    con4 = 1
        # identifying fault code and symptoms
        with open(samTech, "r") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show fault detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Code:" in line:
                    if "F78413" in line:
                        flag2 = 1
                        con1 = 1
                        det_CSCvq53066.append(line.strip())
                    if "F0181" in line:
                        flag2 = 1
                        con2 = 1
                        det_CSCvq53066.append(line.strip())
                    if "F0856" in line:
                        flag2 = 1
                        con3 = 1
                        det_CSCvq53066.append(line.strip())
                elif flag1 and flag2 and "Description:" in line:
                    if "Update Failed on Storage Controller" in line:
                        con1 = 1
                        det_CSCvq53066.append(line.strip())
                    if "Drive state: unconfigured bad" in line:
                        con2 = 1
                        det_CSCvq53066.append(line.strip())
                    if "Activation failed and Activate Status set to failed" in line:
                        con3 = 1
                        det_CSCvq53066.append(line.strip())
                elif flag1 and flag2 and "Affected Object:" in line:
                    flag2 = 0
        if con1 and con2 and con3 and con4:
            found_CSCvq53066 = True
        if found_CSCvq53066:
            sumResult["Check for Server Auto-Install to 4.0(4b) Fails to Activate SAS Controller"] = {"Status": "Found", "Result": "One of the following method can be used to recover the issue:\n1. Decommission and re-acknowledge the affected rack servers.\n2. Re-ack the affected servers.\n3. Reboot the host."}
            detResult["Check for Server Auto-Install to 4.0(4b) Fails to Activate SAS Controller"] = {"Status": "\n".join(det_CSCvq53066), "Result": "Found"}
        else:
            sumResult["Check for Server Auto-Install to 4.0(4b) Fails to Activate SAS Controller"] = {"Status": "Not Found", "Result": ""}
            detResult["Check for Server Auto-Install to 4.0(4b) Fails to Activate SAS Controller"] = "Not Found"

        # C-Series firmware upgrade stays long in process "perform inventory of server"  PNU OS Inventory.
        # DS_UCS_CSCvm55258_C-Series_firmware_upgrade_5cdbd10479bc9db0151a89e6
        # CSCvm55258
        log_msg(INFO, "Check C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory")
        found_CSCvm55258 = False
        con1 = con2 = 0
        det_CSCvm55258 = []
        ser = ""
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show event detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and re.search(r"Description:\s+\[FSM:STAGE:REMOTE-ERROR\]:.*extend-timeout Code:.*sam:dme:ComputePhysicalAssociate:PnuOSInventory", line):
                    con1 = 1
                    det_CSCvm55258.append(line)
                    flag1 = 0
                    break
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show server inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and re.match("Server \d+:", line):
                    ser = line.strip()
                elif flag1 and re.search("Model:\s+HXAF240C-M5SX", line):
                    con2 = 1
                    det_CSCvm55258.append(ser + " ---> " + line.strip())
                    flag1 = 0
                    break
        if con1 and con2:
            found_CSCvm55258 = True
        if found_CSCvm55258:
            det_CSCvm55258.insert(0, "Bug : CSCvm55258 found <-----  C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory")
            sumResult["Check for C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory"] = {"Status": "Found", "Result": "Check the firmware tab to ensure all drives have Activate Status as \"Ready\" and reset the server via KVM/UCSM."}
            detResult["Check for C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory"] = {"Status": "\n".join(det_CSCvm55258), "Result": "Found"}
        else:
            sumResult["Check for C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory"] = {"Status": "Not Found", "Result": ""}
            detResult["Check for C-Series firmware upgrade stays long in process \"perform inventory of server\"  PNU OS Inventory"] = "Not Found"


def new_ucsm_health_checks():
    # New UCSM_Health Checks
    samTech = r"./logFiles/sam_techsupportinfo"
    swTech = "./logFiles/sw_techsupportinfo"
    swTechB = "./logFilesB/sw_techsupportinfo"
    global ucsVersion, fiVersion, bootflashCheck, fiTrdGenCheck, tarVersion, usr_ch
    if os.path.isfile(samTech):
        # UCSM Authentication Domain using a Period or Hyphen
        # CSCvx23029
        log_msg(INFO, "Check UCSM Authentication Domain using a Period or Hyphen")
        found_CSCvx23029 = False
        det_CSCvx23029 = []
        con1 = con2 = con3 = con4 = 0
        conL2_1 = conL2_2 = 0
        conV_1 = conV_2 = 0
        con2304_1 = con2304_2 = 0
        # check UCSM ver == 4.1.3b
        if ucsVersion and ("4.1.3b" in str(ucsVersion) or "4.1(3b)" in str(ucsVersion)):
            con1 = 1
        # identifying fault code and symptoms
        with open(samTech, "r") as f:
            flag1 = flag2 = 0
            for line in f:
                if "`show fault detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Code:" in line:
                    if "F999620" in line:
                        flag2 = 1
                        con2 = 1
                        det_CSCvx23029.append(line.strip())
                    if "F1090" in line:
                        conL2_1 = 1
                    if "F1091" in line:
                        conL2_2 = 1
                    if "F0276" in line:
                        conV_1 = 1
                    if "F0478" in line:
                        con2304_1 = 1
                elif flag1 and flag2 and "Affected Object:" in line:
                    flag2 = 0
        # identifying FI PID with 6454
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show fabric-interconnect detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "PID:" in line:
                    val = line.strip().split("PID: ")[1]
                    if val and "6454" in val:
                        con3 = 1
                        break

        # indentifying period or hypen in Authentication domain
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show auth-domain detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Authentication domain name:" in line:
                    name = line.strip().split("Authentication domain name: ")[1]
                    if name and ("." in name or "-" in name):
                        con4 = 1
                        break
        if con1 and con2 and con3 and con4:
            found_CSCvx23029 = True
        if found_CSCvx23029:
            sumResult["Check UCSM Authentication Domain using a Period or Hyphen"] = {"Status": "Found", "Result": "Check the Bug detail and contact Cisco Technical Support"}
            detResult["Check UCSM Authentication Domain using a Period or Hyphen"] = {"Status": "\n".join(det_CSCvx23029), "Result": "Found"}
        else:
            sumResult["Check UCSM Authentication Domain using a Period or Hyphen"] = {"Status": "Not Found", "Result": ""}
            detResult["Check UCSM Authentication Domain using a Period or Hyphen"] = "Not Found"

        # Local or fallback Authentication failure
        # CSCvx33064
        log_msg(INFO, "Local or fallback Authentication failure")
        found_CSCvx33064 = False
        CSCvx33064_det = ""
        con1 = con2 = con3 = 0
        # check UCSM ver == 4.1.3b
        if ucsVersion and ("4.1.3b" in str(ucsVersion) or "4.1(3b)" in str(ucsVersion)):
            con1 = 1
        # identifying FI PID with 6454
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show fabric-interconnect detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "PID:" in line:
                    val = line.strip().split("PID: ")[1]
                    if val and "6454" in val:
                        con2 = 1
                        break
        # Check Authentication Realm
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show default-auth detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Admin Realm:" in line:
                    val = line.strip().split("Admin Realm: ")[1].strip()
                    if val and "LDAP" in val.upper() or "RADIUS" in val.upper() or "TACACS" in val.upper():
                        con3 = 1
                        CSCvx33064_det = line.strip()
                        break
        if con1 and con2 and con3:
            found_CSCvx33064 = True
        if found_CSCvx33064:
            sumResult["Local or fallback Authentication failure"] = {"Status": "Found", "Result": "Check the Bug detail and contact Cisco Technical Support"}
            detResult["Local or fallback Authentication failure"] = {"Status": CSCvx33064_det, "Result": "Found"}
        else:
            sumResult["Local or fallback Authentication failure"] = {"Status": "Not Found", "Result": ""}
            detResult["Local or fallback Authentication failure"] = "Not Found"

        # Health check between UCSM and UCS central
        log_msg(INFO, "Health check between UCSM and UCS central")
        con1 = con2 = con3 = 0
        ucs_cen_state = "PASS"
        with open(samTech, "r") as f:
            flag1 = 0
            for line in f:
                if "`show control-ep detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Registration Status:" in line:
                    con3 = 1
                    val = line.strip().split("Registration Status:")[1].strip()
                    if val and val.lower() == "registered":
                        con1 = 1
                        break
                elif flag1 and 'Suspend State:' in line:
                    val = line.strip().split("Suspend State:")[1].strip()
                    if val and val.lower() == "Off":
                        con2 = 1

        # with open(samTech, "r") as f:
        #     flag1 = 0
        #     for line in f:
        #         if "`show control-ep fsm status`" in line:
        #             flag1 = 1
        #             continue
        #         elif flag1 and "`show" in line:
        #             flag1 = 0
        #             break
        #         elif flag1 and "Previous Status: " in line:
        #             val = line.strip().split("Previous Status: ")[1].strip()
        #             if val and val.lower() == "register fsm success":
        #                 con2 = 1
        #                 break
        if con1 and con2:
            ucs_cen_state = "PASS"
            sumResult["Health check between UCSM and UCS central"] = {"Status": ucs_cen_state, "Result": ""}
            detResult["Health check between UCSM and UCS central"] = {"Status": "", "Result": "PASS"}
        elif not con3:
            ucs_cen_state = "Not Found"
            sumResult["Health check between UCSM and UCS central"] = {"Status": ucs_cen_state, "Result": "UCS Manager is Not Registered"}
            detResult["Health check between UCSM and UCS central"] = {"Status": "UCS Manager is Not Registered", "Result": "Not Found"}
        else:
            ucs_cen_state = "FAIL"
            sumResult["Health check between UCSM and UCS central"] = {"Status": ucs_cen_state, "Result": "Please check and ensure the reachability between UCS Central and UCS Manager,\nalso verify necessary ports are open.\nRefer this link:\nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/ucs-central/install-upgrade/1-1/b_UCSC_Installation_and_Upgrade_Guide_11/b_UCSC_Installation_and_Upgrade_Guide_11_chapter_010.html#reference_22DE16D447A74611870B3B2E2E3ACE16"}
            detResult["Health check between UCSM and UCS central"] = {"Status": "Please check and ensure the reachability between UCS Central and UCS Manager,\nalso verify necessary ports are open.\nRefer this link:\nhttps://www.cisco.com/c/en/us/td/docs/unified_computing/ucs/ucs-central/install-upgrade/1-1/b_UCSC_Installation_and_Upgrade_Guide_11/b_UCSC_Installation_and_Upgrade_Guide_11_chapter_010.html#reference_22DE16D447A74611870B3B2E2E3ACE16", "Result": "FAIL"}

        log_msg(INFO, "Reserve VLAN issue")
        con1 = con2 = 0
        flag_fis = ["UCS-FI-6248UP","UCS-FI-6296UP","UCS-FI-6332-16UP-U","UCS-FI-6332","UCS-FI-M-6324"]
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = 0
            exit_pattern = r"`[^`]+`"
            for line in f:
                if "`show module`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1:
                    for fi in flag_fis:
                        if fi in line:
                            con1 = 1      
                            break
        vlan_in_range = []
        if con1:
            with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
                flag1 = 0
                shvlan = ""
                for line in f:
                    if "`show vlan`" in line:
                        flag1 = 1
                        continue
                    elif flag1 and re.search(exit_pattern,line):
                        print('exit line is', line)
                        flag1 = 0
                        break
                    elif flag1: 
                        shvlan += "\n" + line
            search_pattern = r"^\s*(\d+)\s"
            
            vlan_numbers = re.findall(search_pattern,shvlan, re.MULTILINE)
            vlan_numbers = [int(vlan) for vlan in vlan_numbers]

            vlan_in_range = [vlan for vlan in vlan_numbers if 3915 <= vlan <= 4042]

        if len(vlan_in_range) != 0:
            sumResult["Reserved VLAN Check"] = {"Status": "Found", "Result":f"Reserved VLANs configured {vlan_in_range}. Take required actions before migration"}
            detResult["Reserved VLAN Check"] = {"Status": "Reserved VLANs configured", "Result":"Found"}
        else:
            sumResult["Reserved VLAN Check"] = {"Status": "Not Found", "Result": ""}
            detResult["Reserved VLAN Check"] = {"Status": "", "Result": "Not Found"}


        # LAN and SAN Pin Groups
        log_msg(INFO, "LAN and SAN Pin Groups")
        con1 = con2 = 0
        Lan_San = False
        with open(samTech, "r") as f:
            flag1 = flag2 = 0
            for line in f:
                if re.match("Pin Group: ", line.strip()):
                    val = line.strip().split("Pin Group: ")[1].strip()
                    if val:
                        con1 = 1
                        break
                if "`show fc-uplink detail expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                elif flag1 and "FC Pin Group:" in line:
                    flag2 = 0
                elif flag1 and flag2 and "Name:" in line:
                    vl = line.strip().split("Name: ")[1].strip()
                    if vl:
                        con2 = 1
                        break
                    flag2 = 0
        if con1 or con2:
            Lan_San = True
        if Lan_San:
            sumResult["LAN and SAN Pin Groups"] = {"Status": "Found", "Result": "Please review your configuration and take necessary steps before the upgrade as you are configured 'pin groups/static pinning'"}
            detResult["LAN and SAN Pin Groups"] = {"Status": "LAN and SAN Pin Groups Found", "Result": "Found"}
        else:
            sumResult["LAN and SAN Pin Groups"] = {"Status": "Not Found", "Result": ""}
            detResult["LAN and SAN Pin Groups"] = {"Status": "", "Result": "Not Found"}

        # VIC 1400 and 6400 Link Flap Issue
        with open(samTech, "r") as fh:
            flag1 = flag2 = flag3 = 0
            for line in fh:
                if "`show server inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 and "Adapter:" in line:
                    flag2 = 1
                elif flag1 and flag2 and "Adapter" in line and "PID" in line and "Vendor" and "Serial" in line and "Overall Status" in line:
                    flag3 = 1
                elif flag1 and flag2 and flag3 and "----" not in line:
                    m = re.search(r"^ *\d ([^\s]*).*$", line)
                    if m:
                        apid = m.group(1)
                        if apid and (apid.strip() == "UCSC-MLOM-C25Q-04" or apid.strip() == "UCSC-PCIE-C25Q-04"):
                            conV_2 = 1
                            break
                    flag2 = 0
                    flag3 = 0

        # Checking sam_tech for 2304 IOM issue:
        with open(samTech, "r") as fh:
            flag1 = flag2 = 0
            for line in fh:
                if "`show chassis inventory expand`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 and re.search(r"IOCard \d+:$", line.strip()):
                    flag2 = 1
                elif flag1 and flag2 and "PID:" in line and "2304" in line:
                    vl = line.strip().split("PID: ")[1].strip()
                    if vl and "2304" in vl and "IOM" in vl:
                        con2304_2 = 1
                        break
                    flag2 = 0

        # Checking Pending Activities Present in UCSM
        log_msg(INFO, "Checking Pending Activities Present in UCSM")
        found_PendingAction = False
        with open(samTech, "r") as fh:
            flag1 = flag2 = 0
            chk1 = 0
            for line in fh:
                if "`show service-profile status`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    flag2 = 0
                    break
                elif flag1 and "Service Profile Name" in line and "Op State" in line:
                    flag2 = 1
                    vl = line.strip().split("  ")[-1].strip()
                    if vl and vl == "Op State":
                        chk1 = 1
                elif flag1 and flag2 and "Pending Reboot" in line:
                    st = line.strip().split("  ")[-1].strip()
                    if st and st == "Pending Reboot" and chk1:
                        found_PendingAction = True
                        break
        if found_PendingAction:
            sumResult["Checking Pending Activities Present in UCSM"] = {"Status": "Found", "Result": "Investigate the reason of pending reboot, connect to TAC if any assistance needed."}
            detResult["Checking Pending Activities Present in UCSM"] = {"Status": "Checking Pending Activities Present in UCSM Found", "Result": "Found"}
        else:
            sumResult["Checking Pending Activities Present in UCSM"] = {"Status": "Not Found", "Result": ""}
            detResult["Checking Pending Activities Present in UCSM"] = {"Status": "", "Result": "Not Found"}

        # Health Check Logic for IOM
        log_msg(INFO, "Checking Health Check Logic for IOM")
        found_IOM = False
        with open(samTech, "r") as fh:
            flag1 = flag2 = 0
            chk_iom1 = chk_iom2 = chk_iom3 = chk_iom4 = chk_iom5 = 0
            for line in fh:
                if "`show fault detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "Code:" in line:
                    if "F0405" in line:
                        chk_iom1 = 1
                        found_IOM = True
                    elif "F0478" in line or "F0376" in line:
                        chk_iom2 = 1
                    elif "F0481" in line:
                        chk_iom3 = 1
                    elif "F0379" in line or "F0731" in line or "F0730" in line:
                        chk_iom4 = 1
                    elif "F0401" in line:
                        chk_iom5 = 1

        with open(samTech, "r") as fh:
            flag1 = flag2a = flag2b = flag2c = flag2d = 0
            val_iom1 = val_iom2 = val_iom3 = val_iom4 = val_iom5 = 0
            for line in fh:
                if "`show chassis iom detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 == 1 and "`show " in line:
                    break
                elif flag1 and "Overall Status:" in line and "Peer Comm Problem" in line:
                    flag2a = 1
                elif flag1 and flag2a and "Peer Comm Status:" in line:
                    flag2a = 0
                    if "Disconnected" in line:
                        val_iom2 = 1
                elif flag1 and "Overall Status:" in line and "Inoperable" in line:
                    flag2b = 1
                elif flag1 and flag2b and "Oper qualifier:" in line:
                    flag2b = 0
                    if "Post Failure" in line:
                        val_iom3 = 1
                elif flag1 and "Overall Status:" in line and "Thermal Problem" in line:
                    flag2c = 1
                elif flag1 and flag2c and "Thermal Status:" in line:
                    flag2c = 0
                    if "LNR" in line:
                        val_iom4 = 1
                elif flag1 and "Overall Status:" in line and "Fabric Unsupported Conn" in line:
                    flag2d = 1
                elif flag1 and flag2d and "Config State:" in line:
                    flag2d = 0
                    if "Unsupported Connectivity" in line:
                        val_iom5 = 1

        if int(chk_iom1 + chk_iom2 + chk_iom3 + chk_iom4 + chk_iom5) > 1:
            found_IOM = True
            if found_IOM:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "Contact TAC ", "Result": "Found"}

        elif int(chk_iom1 + chk_iom2 + chk_iom3 + chk_iom4 + chk_iom5) == 1:
            if chk_iom1:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "Contact TAC ", "Result": "FAIL"}
            elif chk_iom2 and val_iom2:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "1. Wait a few minutes to see if the fault clears. This is typically a temporary issue, and can occur after a firmware upgrade.\n2. Re-insert the I/O module and configure the fabric-interconnect ports connected to it as server ports and wait a few minutes to see if the fault clears.\n3. if it didn’t resolve , Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "1. Wait a few minutes to see if the fault clears. This is typically a temporary issue, and can occur after a firmware upgrade.\n2. Re-insert the I/O module and configure the fabric-interconnect ports connected to it as server ports and wait a few minutes to see if the fault clears.\n3. if it didn’t resolve , Contact TAC", "Result": "FAIL"}
            elif chk_iom3 and val_iom3:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "1. Check the POST results for the I/O module.\n2. Reboot the I/O module.\n3. Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "1. Check the POST results for the I/O module.\n2. Reboot the I/O module.\n3. Contact TAC ", "Result": "FAIL"}
            elif chk_iom4 and val_iom4:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "Contact TAC ", "Result": "FAIL"}
            elif chk_iom5 and val_iom5:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "Step 1 Verify that the correct number of links are configured in the chassis discovery policy.\n Step 2Check the state of the I/O module links.\n Step 3 Reacknowledge the chassis.\n Step 4 If the above actions did not resolve the issue,  Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "Step 1 Verify that the correct number of links are configured in the chassis discovery policy.\n Step 2Check the state of the I/O module links.\n Step 3 Reacknowledge the chassis.\n Step 4 If the above actions did not resolve the issue,  contact TAC ", "Result": "FAIL"}
            else:
                sumResult["Health Check for IOM"] = {"Status": "FAIL", "Result": "Contact TAC "}
                detResult["Health Check for IOM"] = {"Status": "Contact TAC ", "Result": "FAIL"}
        elif int(chk_iom1 + chk_iom2 + chk_iom3 + chk_iom4 + chk_iom5) == 0:
            sumResult["Health Check for IOM"] = {"Status": "PASS", "Result": ""}
            detResult["Health Check for IOM"] = {"Status": "", "Result": "PASS"}

        # Core Files available in UCSM check
        log_msg(INFO, "Checking Core Files available in UCSM check")
        found_corefile = False
        corecount = 0
        cFile_list = []
        with open(samTech, "r") as fh:
            flag1 = flag2 = flag3 = 0
            for line in fh:
                if "`show cores detail`" in line:
                    flag1 = 1
                elif flag1 and "`show" in line:
                    flag1 = 0
                    flag2 = 0
                elif flag1 and "Core Files:" in line:
                    flag2 = 1
                elif flag1 and flag2 and "Name:" in line:
                    flag3 = 1
                    name_core = ""
                    name_core+= line.strip()
                elif flag1 and flag2 and flag3 and "Timestamp:" in line:
                    timestp = line.strip().split("Timestamp:")[1].strip()
                    if timestp:
                        tmstp = datetime.datetime.strptime(timestp, "%Y-%m-%dT%H:%M:%S.%f")
                        tm = start_time - tmstp
                        #print("Diff in time: " + str(tm.days))
                        if int(tm.days) <= 60 and name_core:
                            corecount += 1
                            dict_core = ""
                            dict_core += str(corecount) + ". " + name_core
                            dict_core += "\n" + line.strip()
                            if corecount < 6:
                                cFile_list.append(dict_core)
                            else:
                                break
                    flag3 = 0

        if cFile_list:
            cFile_list.append("\nPlease Contact TAC")
            sumResult["Core Files available in UCSM Check"] = {"Status": "Found", "Result": "\n".join(cFile_list)}
            detResult["Core Files available in UCSM Check"] = {"Status": "\n".join(cFile_list), "Result": "Found"}
        else:
            sumResult["Core Files available in UCSM Check"] = {"Status": "Not Found", "Result": "No core files were found in last 60 days"}
            detResult["Core Files available in UCSM Check"] = {"Status": "No core files were found in last 60 days", "Result": "Not Found"}

    if os.path.isfile(swTech):
        # Disjoint L2 potential misconfiguration
        log_msg(INFO, "Disjoint L2 potential misconfiguration ")
        found_L2_Disjoint = False
        det_L2_Disjoint = []
        con1 = con2 = 0
        conV_3 = conV_4 = conV_5 = 0
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show platform software enm internal info vlandb all`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and re.search("vlan_id \d+", line):
                    flag2 = 1
                    vlan = line
                elif flag1 and flag2 and "Membership:" in line:
                    flag3 = 1
                elif flag1 and flag2 and flag3 and ("Po1" in line or "Eth" in line):
                    flag2 = 0
                    flag3 = 0
                    val = line.strip().split("  ")
                    if val and len(val) > 1:
                        con1 = 1
                        det_L2_Disjoint.append(vlan)
                        det_L2_Disjoint.append("Membership: " + str(line))

        if con1 and conL2_1 and conL2_2:
            found_L2_Disjoint = True
        if found_L2_Disjoint:
            sumResult["Disjoint L2 potential misconfiguration"] = {"Status": "Found", "Result": "Deploy Layer 2 Disjoint Networks Upstream in End Host Mode\nhttps://www.cisco.com/c/en/us/solutions/collateral/data-center-virtualization/unified-computing/white_paper_c11-692008.html\nIn case of further assistance needed contact Cisco Technical Support."}
            detResult["Disjoint L2 potential misconfiguration"] = {"Status": "\n".join(det_L2_Disjoint), "Result": "Found"}
        else:
            sumResult["Disjoint L2 potential misconfiguration"] = {"Status": "Not Found", "Result": ""}
            detResult["Disjoint L2 potential misconfiguration"] = "Not Found"

        # VIC 1400 and 6400 Link Flap Issue
        log_msg(INFO, "VIC 1400 and 6400 Link Flap Issue")
        found_CSCvu25233 = False
        # check UCSM ver < 4.1(2a)
        if ucsVersion:
            ver_chk = ucsVersion.split("(")
            if float(ver_chk[0]) < 4.1:
                conV_3 = 1
            elif ver_chk[0] == '4.1':
                if ver_chk[1].split(")")[0].strip() < '2a':
                    conV_3 = 1
        # Check show interface transceiver details
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show interface transceiver detail`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "cisco product id is" in line:
                    m = re.search(r"cisco product id is ([^\s]*)$", line)
                    if m:
                        vl = m.group(1)
                        if vl and (vl == "SFP-H25G-CU3M" or vl == "SFP-H25G-CU5M"):
                            conV_4 = 1
                            break
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show inventory`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "PID" in line:
                    print(line)         
                    pd = line.strip().split(",")[0].strip().split("PID: ")[1].strip()
                    print (pd)
                    if pd and "64" in pd:
                        conV_5 = 1
                        break

        if conV_1 and conV_2 and conV_3 and conV_4 and conV_5:
            found_CSCvu25233 = True
        if found_CSCvu25233:
            sumResult["VIC 1400 and 6400 Link Flap Issue"] = {"Status": "Found", "Result": "UCSM infrastructure firmware and host firmware need to be upgraded to 4.1(2a) or above"}
            detResult["VIC 1400 and 6400 Link Flap Issue"] = {"Status": "VIC 1400 and 6400 Link Flap Issue Found\nUCSM infrastructure firmware and host firmware need to be upgraded to 4.1(2a) or above", "Result": "Found"}
        else:
            sumResult["VIC 1400 and 6400 Link Flap Issue"] = {"Status": "Not Found", "Result": ""}
            detResult["VIC 1400 and 6400 Link Flap Issue"] = "Not Found"

        # 2304 IOMs disconnect and re - connect during firmware update step
        log_msg(INFO, "2304 IOMs disconnect and re - connect during firmware update step")
        found_2304_iom = False
        con2304_3 = 0
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show inventory`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "DESCR: \"UCS 6300 Series Fabric Interconnect\"" in line:
                    con2304_3 = 1
                    break
                elif flag1 and "PID" in line:
                    pd = line.strip().split(",")[0].strip().split("PID: ")[1].strip()
                    if pd and re.search(r"64\d\d", str(pd)):
                        con2304_3 = 1
                        break
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = flag3 = 0
            for line in f:
                if "`show logging nvram`" in line:
                    flag1 = 1
                    continue
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and "[F0478][critical]" in line and "IOM" in line and "equipment-inaccessible" in line:
                    con2304_1 = 1
                    break
        if not con2304_1 and os.path.isfile(swTechB):
            with open(swTechB, "r", encoding="utf-8", errors="ignore") as f:
                flag1 = flag2 = flag3 = 0
                for line in f:
                    if "`show logging nvram`" in line:
                        flag1 = 1
                        continue
                    elif flag1 and "`show" in line:
                        flag1 = 0
                        break
                    elif flag1 and "[F0478][critical]" in line and "IOM" in line and "equipment-inaccessible" in line:
                        con2304_1 = 1
                        break

        if con2304_1 and con2304_2 and con2304_3:
            found_2304_iom = True
        if found_2304_iom:
            sumResult["Check 2304 IOMs disconnect and re-connect during firmware update step"] = {"Status": "Found", "Result": "Perform a manual UCS Infrastructure upgrade.In case of further assistance contact Cisco Technical Support."}
            detResult["Check 2304 IOMs disconnect and re-connect during firmware update step"] = {"Status": "2304 IOMs disconnect and re-connect during firmware update step Found", "Result": "Found"}
        else:
            sumResult["Check 2304 IOMs disconnect and re-connect during firmware update step"] = {"Status": "Not Found", "Result": ""}
            detResult["Check 2304 IOMs disconnect and re-connect during firmware update step"] = "Not Found"

        # Number of Interface and Number of flogis
        log_msg(INFO, "Number of Interface up and Number of flogis matching")
        fc_count = 0
        eth_count = 0
        flogi_count = 0
        with open(swTech, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = 0
            for line in f:
                if "`show interface brief`" in line:
                    flag1 = 1
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and re.match(r"^fc\d+/\d+ ", line) and " trunking " in line:
                    fc_count += 1
                elif flag1 and re.match(r"^Eth\d+/\d+ ", line) and " up " in line:
                    eth_count += 1
            for line in f:
                if "`show npv flogi-table`" in line:
                    flag2 = 1
                elif flag2 and "`show" in line:
                    flag2 = 0
                elif flag2 and re.search(r"Total number of flogi = (\d+)", line):
                    try:
                        flogi_count = int(re.search(r"Total number of flogi = (\d+)", line).group(1))
                    except exception:
                        flogi_count = 0
                    break

        log_msg(INFO, "Number of Interface up and Number of flogis matching")
        fc_countB = 0
        eth_countB = 0
        flogi_countB = 0
        with open(swTechB, "r", encoding="utf-8", errors="ignore") as f:
            flag1 = flag2 = 0
            for line in f:
                if "`show interface brief`" in line:
                    flag1 = 1
                elif flag1 and "`show" in line:
                    flag1 = 0
                    break
                elif flag1 and re.match(r"^fc\d+/\d+ ", line) and " trunking " in line:
                    fc_countB += 1
                elif flag1 and re.match(r"^Eth\d+/\d+ ", line) and " up " in line:
                    eth_countB += 1
            for line in f:
                if "`show npv flogi-table`" in line:
                    flag2 = 1
                elif flag2 and "`show" in line:
                    flag2 = 0
                elif flag2 and re.search(r"Total number of flogi = (\d+)", line):
                    try:
                        flogi_countB = int(re.search(r"Total number of flogi = (\d+)", line).group(1))
                    except exception:
                        flogi_countB = 0
                    break
        intf_cnt = []
        intf_cnt.append("Primary: \n  FC Port Trunking Count: " + str(fc_count) + ",\n  Eth up Port: " + str(eth_count) + ",\n  Flogi Count: " + str(flogi_count))
        intf_cnt.append("Secondary: \n  FC Port Trunking Count: " + str(fc_countB) + ",\n  Eth up Port: " + str(eth_countB) + ",\n  Flogi Count: " + str(flogi_countB))
        if intf_cnt:
            sumResult["Number of Interface up and Flogi Matching on FI"] = {"Status": "---", "Result": "\n".join(intf_cnt)}
            detResult["Number of Interface up and Flogi Matching on FI"] = {"Status": "\n".join(intf_cnt), "Result": "---"}
        else:
            sumResult["Number of Interface up and Flogi Matching on FI"] = {"Status": "---", "Result": "\n".join(intf_cnt)}
            detResult["Number of Interface up and Flogi Matching on FI"] = {"Status": "\n".join(intf_cnt), "Result": "---"}

        # Jumbo/Standard MTU Check

        log_msg(INFO, "Verifying Jumbo/Standard MTU Check")
        try:
            mtu_chk = check_jumbo_mtu(swTech)
        except Exception as e:
            log_msg(INFO, "Exception Hit while MTU check: " + str(e))
            mtu_chk = ""
        if mtu_chk:
            sumResult["Jumbo or Standard MTU Check"] = {"Status": mtu_chk.get("Status", ""), "Result": mtu_chk.get("Report", "")}
            detResult["Jumbo or Standard MTU Check"] = {"Status": mtu_chk.get("Result", ""), "Result": mtu_chk.get("Status", "")}
        else:
            sumResult["Jumbo or Standard MTU Check"] = {"Status": "Not Found", "Result": ""}
            detResult["Jumbo or Standard MTU Check"] = {"Status": "", "Result": "Not Found"}


def check_upgrade_path(cur, tar):
    """
    WEB SCRAPE FOR THE UPGRADE VERSION CHECK
    Author: Nachiketa
    """
    cur = cur[:5] + ")"
    tar = tar[:5] + ")"
    log_msg(INFO, "Entering upgrade check")
    log_msg(INFO, "Current version : " + cur)
    log_msg(INFO, "Target version : " + tar)
    header_list = [" "]
    dir_upg = []
    ind_upg = []
    upg_thrg = ""
    flag1 = flag2 = flag3 = 0
    url = "https://www.cisco.com/c/dam/en/us/td/docs/unified_computing/ucs/ucs-manager/UCSM-upgrade-downgrade-matrix/UCSM-Upgrade-path-Overview.htm"
    f = urllib.request.urlopen(url)
    myfile = f.readlines()
    header_flag = 0
    count_col = 0
    for line in myfile:
        line = line.decode("utf-8")
        if "<table" in line and "style='border-collapse:" in line and "border=0" in line:
            flag1 = 1
        elif flag1 == 1 and "</table>" in line:
            flag1 = 0
        elif flag1 == 1 and "<tr" in line:
            flag2 = 1
            flag3 = 0
            header_flag += 1
            count_col = -1
        elif flag1 == 1 and flag2 == 1 and "</tr>" in line:
            flag2 = 0
            flag3 = 0
        elif flag2 == 1 and flag1 == 1 and "<td" in line and "</td>" in line:
            if cur in line and str(cur) + "</td>" in line:
                flag3 = 1
            count_col += 1
            val = line.strip().split(">")[1].split("<")[0]
            if "&nbsp" in val:
                pass
            if header_flag == 1 and re.match(r"\d+.\d+\(*\d*\)*", val):
                header_list.append(val)
            elif flag3 == 1 and re.match(r"^D$", val):
                try:
                    dir_upg.append(header_list[count_col].strip())
                except Exception:
                    pass
            elif flag3 == 1 and re.match(r"^I$", val):
                try:
                    ind_upg.append(header_list[count_col].strip())
                    if cur in line and tar in line:
                        upg_thrg = line.strip().split("-&gt;")[1].strip()
                        logger.info("Upgrade through: " + str(upg_thrg))
                except Exception:
                    pass
    log_msg(INFO, "versions available in header: " + str(header_list))
    log_msg(INFO, "Direct upgrade list : " + str(dir_upg))
    log_msg(INFO, "Step upgrade list : " + str(ind_upg))
    if tar in dir_upg:
        log_msg(INFO, "Direct upgrade")
        path = cur + " ==> " + tar
        logger.info(path)
        return path
    elif tar in ind_upg:
        log_msg(INFO, "Step upgrade")
        path = cur + " ==> " + upg_thrg + " ==> " + tar
        log_msg(INFO, str(path))
        return path
    else:
        log_msg(INFO, "Target version not found")
        return False


def display_result():
    # Display the Summary results on console
    log_msg(INFO, "Print the Summary Result")
    st = PrettyTable(hrules=ALL)
    st.field_names = ["SlNo", "Name", "Status", "Comments"]
    st.align = "l"
    st._max_width = {"Name": 65,"Comments": 65}
    fault_flag = False
    for i, k in enumerate(sumResult):
        try:
            if type(sumResult[k]) == list:
                st.add_row([i + 1, k, "\n".join(sumResult[k]), ""])
            elif type(sumResult[k]) == dict:
                st.add_row([i + 1, k, sumResult[k]["Status"], sumResult[k]["Result"]])
            else:
                st.add_row([i + 1, k, sumResult.get(k, ""), ""])
        except Exception:
            continue
    print("\nSummary Result:")
    print(st)
    # Additional caveats to crosscheck
    """Commenting Additional Caveats crosscheck segment"""
    """
    print("\nAdditional caveats to crosscheck:")
    for i, c in enumerate(caveatsList):
        print(str(i+1) + ". " + c)
    """
    # Major Faults
    if majorFault:
        print("\nFaults with Severity Major:")
        if len(majorFault) <= 5:
            for line in majorFault:
                print(line)
        else:
            fault_flag = True
            for cnt, line in enumerate(majorFault):
                if int(cnt) < 5:
                    print(line)
    # Critical Faults
    if criticalFault:
        print("\nFaults with Severity Critical:")
        if len(criticalFault) <= 5:
            for line in criticalFault:
                print(line)
        else:
            fault_flag = True
            for cnt, line in enumerate(criticalFault):
                if int(cnt) < 5:
                    print(line)

    if usr_ch.lower() == "2":
        print("")
        print(note)

    if fault_flag:
        print(end_note)
        print("b. Please visit the Summary Report/ Main Report to view all the Major and Critical Fault alerts.")
    else:
        print(end_note)


def create_summary_report():
    # Create Summary Report
    log_msg(INFO, "Create the Summary Report file")
    filename = "UCS_HealthCheck_Tool_Summary_Report_" + get_date_time() + ".txt"
    with open(filename, "w") as fh:
        fh.write("#" * 80)
        fh.write("\n")
        fh.write("\t\t\t\tUCS Health Check Tool " + str(toolversion))
        fh.write("\n")
        fh.write("\t\t\tUCS Health Check Tool Summary Report:")
        fh.write("\n")
        fh.write("#" * 80)
        fh.write("\n\n")
        fh.write("UCSM Version: " + ucsVersion)
        fh.write("\n\n")
        if usr_ch.lower() == '2':
            fh.write("Target Version: " + tarVersion)
            fh.write("\n\n")
            fh.write("Upgrade Path: " + upgradePath)
            fh.write("\n")
        # Summary Result
        dt = PrettyTable(hrules=ALL)
        dt.field_names = ["SlNo", "Name", "Status", "Comments"]
        dt.align = "l"
        for i, k in enumerate(sumResult):
            try:
                if type(sumResult[k]) == list:
                    dt.add_row([i + 1, k, "\n".join(sumResult[k]), ""])
                elif type(sumResult[k]) == dict:
                    dt.add_row([i + 1, k, sumResult[k]["Status"], sumResult[k]["Result"]])
                else:
                    dt.add_row([i + 1, k, sumResult.get(k, ""), ""])
            except Exception:
                continue
        fh.write("\nSummary Result:")
        fh.write("\n")
        fh.write(str(dt))
        fh.write("\n")
        # Major Faults
        if majorFault:
            fh.write("\nFaults with Severity Major:")
            for line in majorFault:
                fh.write("\n")
                fh.write(line)

        fh.write("\n")
        # Critical Faults
        if criticalFault:
            fh.write("\nFaults with Severity Critical:")
            for line in criticalFault:
                fh.write("\n")
                fh.write(line)
        fh.write("\n")
        fh.write("\n")
        fh.write(note)
        fh.write("\n")


def create_main_report():
    # Create Main Report
    log_msg(INFO, "Create the Main Report file")
    filename = "UCS_HealthCheck_Tool_Main_Report_" + get_date_time() + ".txt"
    with open(filename, "w") as fh:
        fh.write("#" * 100)
        fh.write("\n")
        fh.write("\t\t\t\t\t\t\tUCS Health Check Tool " + str(toolversion))
        fh.write("\n")
        fh.write("\t\t\t\t\t\tUCS Health Check Tool Main Report:")
        fh.write("\n")
        fh.write("#" * 100)
        fh.write("\n\n")
        fh.write("UCSM Version: " + ucsVersion)
        fh.write("\n\n")
        if usr_ch == '2':
            fh.write("Target Version: " + tarVersion)
            fh.write("\n\n")
            fh.write("Upgrade Path: " + upgradePath)
            fh.write("\n")
        # Detail Result
        dt = PrettyTable(hrules=ALL)
        dt.field_names = ["Name", "Status", "Comments"]
        dt.align = "l"
        for k in detResult.keys():
            try:
                if type(detResult[k]) == list:
                    dt.add_row([k, "\n".join(detResult[k]), ""])
                elif type(detResult[k]) == dict:
                    dt.add_row([k, detResult[k]["Status"], detResult[k]["Result"]])
                else:
                    dt.add_row([k, detResult.get(k, ""), ""])
            except Exception:
                continue
        fh.write("\n")
        fh.write(str(dt))
        fh.write("\n")
        # Additional caveats to crosscheck
        fh.write("\n")
        # Major Faults
        if majorFault:
            fh.write("\nFaults with Severity Major:")
            for line in majorFault:
                fh.write("\n")
                fh.write(line)
        fh.write("\n")
        # Critical Faults
        if criticalFault:
            fh.write("\nFaults with Severity Critical:")
            for line in criticalFault:
                fh.write("\n")
                fh.write(line)
        fh.write("\n")
        fh.write("\n")
        fh.write(note)
        fh.write("\n")
    log_stop()


###############################################################################
# Main Starts here
###############################################################################
if __name__ == "__main__":
    # UCS Health Check - Pre-Upgrade Check
    # Check Arguments
    arg = ""

    if len(sys.argv) > 1:
        try:
            arg = (sys.argv[1]).lower()
        except Exception:
            pass
    if arg == "-h" or arg == "--help" or arg == "help":
        print("\n\t\t UCS Health Check Tool " + str(toolversion))
        print("\nRun before upgrading the UCS Host")
        print("\nFor Test report run as below:")
        print("\t python UCSTool.py")
        sys.exit(0)

    # Log file declaration
    log_file = "UCS_HealthCheck_Tool_" + get_date_time() + ".log"
    log_name = "UCSTOOL"
    log_start(log_file, log_name, INFO)

    # Print Tool Info
    print("\n\t\t UCS Health Check Tool " + str(toolversion))
    log_msg(INFO, "UCS Health Check Tool version: " + str(toolversion))
    log_msg(INFO, "UCS Health Check Tool Build Date: " + str(builddate))

    # Get the UCSM Bundle
    filePath = input("\nEnter the UCSM file path: ")
    log_msg(INFO, "UCSM file path: " + filePath)
    usr_ch = input("""\nPress 1 for UCSM Health Check\nPress 2 for PreUpgrade Check\nEnter your choice (1/2): """)
    if usr_ch.lower() == "2":
        tarVersion = input("\nEnter the UCS Target Version [Ex:4.1(1x)]: ")
        log_msg(INFO, "UCS Target Version: " + tarVersion)
    elif usr_ch.lower() == "1":
        log_msg(INFO, "User opted to proceed without Upgrade path check ")
    else:
        log_msg(INFO, "Entered Option Doesn't exist")
        print("Entered Option Doesn't exist -- Quitting")
        sys.exit(0)

    if os.path.isfile(filePath):
        pass
    else:
        log_msg(INFO, "Invalid file path: " + filePath)
        log_msg("", "Invalid file path: " + filePath)
        sys_exit(0)

    # Extract the file
    # Progressbar
    pbar = ProgressBarThread()
    pbar.start("\nLog Extraction: ")
    extraction = extract_files(filePath)
    pbar.stop("COMPLETED")
    if not extraction:
        log_msg(INFO, "Primary file not found")
        log_msg("", "Primary file not found")
        sys_exit(0)

    print("")
    # Result Variables

    sumResult = {}
    detResult = {}
    primary = ""
    subordinate = ""
    ucsVersion = ""
    fiVersion = ""
    upgradePath = ""
    majorFault = []
    criticalFault = []
    safeshutCheck = False
    bootflashCheck = False
    fiTrdGenCheck = False
    caveatsList = ["CSCvd52310: ESXi 6.5 network connectivity lost during failover",
                   "CSCvq28261: PSUs shutdown accidentally - 2300 IOMs",
                   "CSCvr08327: PSUs shutdown accidentally - 2200 IOMs",
                   "CSCvq25021: Default host FW policy/prepare: Server reboots without user-ack on server firmware upgrade",
                   "CSCvo13678: BladeAG Core due to GPU Attribute Handling : Applicable if target version is 4.0.2a|b",
                   "CSCvk36317: Primary Vlan out side ucs unable to talk to isolated Vlan on ucs after upgrade to 3.2.3* or 4.0.1*",
                   "CSCvh87378: PVLAN communication between community and primary vlan broken after upgrade to 3.2.2",
                   "CSCvm68038: Stale samdme sessions on Subordinate FI (UCSM 3.2)",
                   "CSCvr98210: LLDP disabled after UCSM 4.0 Upgrade"]

    note = "We would recommend Customers should complete the below prior to an upgrade: \
            \na. Review firmware release notes \
            \nb. Review compatibility \
            \nc. Upload required images \
            \nd. Generate/Review UCSM show tech \
            \ne. Determine vulnerable upgrade bugs and complete pro-active workaround \
            \nf. Verify FI HA and UCSM PMON status \
            \ng. Generate all configuration and full state backups (right before upgrade)\
            \nh. Verify data path is ready (right before upgrade)\
            \ni. Disable call home (right before upgrade)"
    end_note = "\nNOTE:\
            \na. All reports and logs will be saved in the same location from where the script was executed."

    # Check Cluster State
    check_cluster_state()
    log_msg(INFO, "Primary: " + primary)
    log_msg(INFO, "Subordinate: " + subordinate)

    check_process_state()
    check_file_system()
    check_fi_version()
    check_sam_tech()

    # Check Known Issues
    check_known_issues()

    # New MU Bug Checks
    new_mu_checks()

    # New UCSM Health Checks
    new_ucsm_health_checks()

    # Print Summary Result
    display_result()

    # Create Summary Report
    create_summary_report()

    # Create Main Report
    create_main_report()

    # End
    sys.exit(0)
