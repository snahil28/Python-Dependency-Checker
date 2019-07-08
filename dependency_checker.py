"""

This tool identifies all dependencies with publicly known vulnerabilties in a Python based project that are specified in 'requirements.txt' file and can be installed using Pip (Python package installer).

"""

import os
import sys
import argparse
import requests
import datetime
import matplotlib.pyplot as plt
from packaging import version
from matplotlib import cm
from pkg_resources import parse_version 
from typing import Dict, List, TextIO, Any


REQS_FILE = "requirements.txt"
VUL_DB_API_URL = "https://vuldb.com/?api"
PYPI_URL = "https://pypi.python.org/pypi/"
VULN_GRAPH = "Vul_Distb_Graph.png"
GRAPH_TITLE = "Vulnerability distribution of the project dependencies"
REPORT = "Analysis_Report.html"
VUL_DB_API_KEY = os.environ['API_KEY']

def is_dir_path_valid(path: str) -> str:

    # Check if the proj_path argument is valid or not
    if os.path.isdir(path):
        return path
    else:
        raise argparse.ArgumentTypeError(f":{path} is not a valid path")
        
        
def parse_arguments() -> str:
    
    # Create an argument parser 
    arg_parser = argparse.ArgumentParser(description='Analyze project dependencies.')
    
    # Add the proj_path argument with type to the parser
    arg_parser.add_argument('path', type=is_dir_path_valid, help='path of a project to scan for vulnerabilties')
    
    args = arg_parser.parse_args()
    proj_path = (vars(args)['path'])
    return proj_path
        
        
def get_reqs_loc(proj_path: str) -> str:
    
    reqs_loc = ""
    try:
        # Search project directory for requirements.txt file
        for root, dirs, files in os.walk(proj_path):
            if REQS_FILE in files:
                reqs_loc = os.path.join(root, REQS_FILE)
        if not reqs_loc:
                raise ValueError
    except:
        print(('No requirements.txt file present in the directory: {}'.format(proj_path)))
        
    return reqs_loc
      
    
def get_proj_deps(reqs_loc: str) -> Dict[str, str]:

    dependencies = {}
    reqs_file = open(reqs_loc,"r") 
    
    # For every requirement present in the file, get package name and version and then add it to the dictionary
    for line in reqs_file:
        if line.find("==") >= 0:
            (pckg_name, pckg_version) = line.split("==")
            dependencies[pckg_name] = pckg_version.strip()
        else:
            continue
        
    reqs_file.close() 
    return dependencies


def compare_versions(ver_1: str,ver_2: str) -> bool:
    
    ver1_arr = ver_1.split(".")
    ver2_arr = ver_2.split(".")
    len_diff = len(ver2_arr)-len(ver1_arr)
    
    if len_diff>0:
        if ver1_arr == ver2_arr[:-1]:
            return True
        else:
            return False
    else:
        if ver1_arr[:-1] == ver2_arr[:-1]:
            return True
        else:
            return False
        
               
def get_proj_vulns(proj_deps: Dict[str, str]) -> Dict[str, Any]:
    
    proj_vulns = {}
    for pckg_name,pckg_version in proj_deps.items():
        pckg_cves = get_pckg_cves(pckg_name.strip(),pckg_version)
        proj_vulns[pckg_name] = pckg_cves
    return proj_vulns
 
    
def get_pckg_details(pckg_name: str) -> Dict[str, Any]:
    
    # Fetch package's details from Vuldb
    data = {
        'apikey': VUL_DB_API_KEY,
        'advancedsearch':'product:' + pckg_name
    }
    try:
        vul_resp = requests.post(VUL_DB_API_URL,data=data)
        pckg_details = vul_resp.json()
        
    except:
        print('Problem in fetching results from the Vuldb API')
    
    return pckg_details


def check_version_in_range(versions: str, pckg_version: str) -> bool:
    
    # Check each version range
    for ver in versions:
        # Version matches then add it to the vulnerable package list
        if version.parse(pckg_version) == version.parse(ver):
            return True
        # Else check if it falls in the range and add to the list if present   
        elif (version.parse(pckg_version) < version.parse(ver) and len(pckg_version)<=len(ver)):
            match = compare_versions(pckg_version,ver)
            if match:
                return True
            else:
                continue
                
    return False


def parse_details(pckg_details: Dict[str, Any], pckg_name: str, pckg_version: str) -> List[Any]:
    
    pckg_cve = []
    
    # Check if there are any CVEs in the response for the package
    if 'result' in pckg_details.keys():
        
        # fetch all the vulnerabilities
        vuln_list = (pckg_details['result'])
        
        # Each vulnerability has an entry which has a title, where package description alongwith version is given
        # Parse through each entry's title and compare pckg versions with the version that's being used in the project
        for vul in vuln_list:
            vul_entry = vul['entry']
            vul_title = vul_entry['title']
            pckg_desc = pckg_name + " up to "
            is_version_present = vul_title.lower().find(pckg_desc.lower())
            
            # Version present in the vulnerabiltiy description
            if vul_title.find(pckg_version) != -1:
                pckg_cve.append(vul)
                
            # Else check the range of the versions given in the title    
            elif is_version_present != -1:
                
                # Get the range from the description
                start_range = vul_title.lower().index(pckg_desc.lower()) + len(pckg_desc)
                ver_str = vul_title[start_range:].split(" ")[0]
                
                # Separate the versions if more than one given
                versions = ver_str.split("/")
                
                # Check if version lies in any of the ranges described in the title
                is_version_in_range = check_version_in_range(versions,pckg_version)
                
                if is_version_in_range:
                    pckg_cve.append(vul)
                    
            else:
                continue
                
    return pckg_cve        
 
    
def get_pckg_cves(pckg_name: str, pckg_version: str) -> List[Any]:
    
    pckg_details = get_pckg_details(pckg_name)
    pckg_cve = parse_details(pckg_details,pckg_name,pckg_version)
    return pckg_cve


def get_project_summary(proj_vuln: Dict[str, Any]) -> Dict[str, Any]: 
    
    # Get relevant details from the results
    proj_details = {}
    
    for pckg_name, cve_list in proj_vuln.items():
        pkg_details = []
        for cve in cve_list:
            cve_detail = {}
            cve_detail["Title"] = cve["entry"]["title"]
            cve_detail["Date created"] = cve["advisory"]["date"]
            cve_detail["Risk"] = cve["vulnerability"]["risk"]["name"]
            cve_detail["CVE"] = cve["source"]["cve"]["id"]
            pkg_details.append(cve_detail)
            
        proj_details[pckg_name] = pkg_details
        
    return proj_details


def draw_graph(proj_details: Dict[str, Any]) -> TextIO:
    
    # Draw vulnerability distribution graph of project dependencies and save it
    pckg_name_label = []
    pckg_vul_size = []

    for pckg_name, pckg_details in proj_details.items():
        if len(proj_details[pckg_name]) > 0:
            pckg_name_label.append(pckg_name)
            pckg_vul_size.append(len(proj_details[pckg_name]))
        
    if len(pckg_vul_size)>0 and len(pckg_name_label)>0 and len(pckg_vul_size)==len(pckg_name_label):
        plt.pie(pckg_vul_size, labels=pckg_name_label,
        autopct='%1.1f%%', shadow=True, startangle=140)
        plt.title(GRAPH_TITLE)
        plt.axis('equal')
        plt.savefig(VULN_GRAPH)
        
    
def get_latest_version(pckg_name: str) -> str:
    
    # Get latest upstream version of a package
    url = PYPI_URL + f'{pckg_name}/json'
    try:
        releases = requests.get(url).json()['releases']
        latest_ver = sorted(releases, key=parse_version, reverse=True)[0]
    except:
        print('Problem in fetching results from the Vuldb API')
        
    return latest_ver


def generate_report(proj_details: Dict[str, Any], proj_deps: Dict[str, str]) -> None:
   
    f_report = open(REPORT,'x')
    f_report.write ('<head><b><h1> <u> Vulnerability Analysis Report of Third Party Dependencies of a Project </u></h1></b></head><br>')
    f_report.write('<p>This is the Vulnerabiltiy Analysis of third party dependencies for the project: ' + proj_path + '</p>')
    
    # Creation of dependency table
    f_report.write('<br>')
    f_report.write('<h3> Third party dependencies found in the project </h3>')
    f_report.write("<p> Third party libraries were fetched from the 'requirements.txt' for the project: " + proj_path + ". <br> The below list shows the currently installed version of a dependency and latest available version of the same. This gives us the list of outdated dependencies that are still being used in the project and should be upgraded.</p>")
    f_report.write('<table style="margin: 0px;" width="50%" border="1px solid black" border-collapse="collapse">')
    f_report.write('<tr>')
    f_report.write('<th> Dependency Name </th>')
    f_report.write('<th> Installed Version </th>')
    f_report.write('<th> Latest Version </th>')
    f_report.write('</tr>')
    
    for dep_name, dep_version in proj_deps.items():
        f_report.write('<tr>')
        f_report.write('<td>%s</td>' % dep_name)
        f_report.write('<td>%s</td>' % dep_version)
        f_report.write('<td>%s</td>' % get_latest_version(dep_name))
        f_report.write('</tr>')
    f_report.write ('</table>')
    f_report.write ('<br><br>')
    
    # Creation of vulnerabiltiy table
    f_report.write('<h3> Vulnerabilities found in the project dependencies </h3>')
    f_report.write('<p> After fetching all the dependencies of the project, they were analyzed to find if they are vulnerable or not using the data from <a href="https://vuldb.com/">Vuldb (https://vuldb.com/).</a>')
    f_report.write('<p>Below is the detailed explanation of the vulnerabilties found in the project. It includes the vulnerable dependency being used, summary describing what makes it insecure, Common Vulnerabiltiy Exposure(CVE), date of creation of this CVE created and the risk associated with the vulnerabiltiy. There are three levels of risk associated with a vulnerabiltiy- high, medium and low as shown and highlighted in the table below.</p>')
    
    #Legend explaining the risk of the vulnerability
    f_report.write('<div style = "text-align: left; margin-bottom: 5px; font-weight: bold; font-size: 90%;">Vulnerability Risk</div>')
    f_report.write('<ul style= "margin: 0;margin-bottom: 5px; padding: 0; float: left;list-style: none;">')
    f_report.write('<li style="font-size: 80%;list-style: none;margin-left: 0;line-height: 18px;margin-bottom: 2px;">')
    f_report.write('<span style="background:#FFFF00; display: block; float: left;height: 16px;width: 30px;margin-right: 5px;margin-left: 0;border: 1px solid #999;"></span>Low</li>')
    f_report.write('<li style="font-size: 80%;list-style: none;margin-left: 0;line-height: 18px;margin-bottom: 2px;">')
    f_report.write('<span style="background:#FFA500;display: block; float: left;height: 16px;width: 30px;margin-right: 5px;margin-left: 0;border: 1px solid #999;"></span>Medium</li>')
    f_report.write('<li style="font-size: 80%;list-style: none;margin-left: 0;line-height: 18px;margin-bottom: 2px;">')
    f_report.write('<span style="background:#FF0000;display: block; float: left;height: 16px;width: 30px;margin-right: 5px;margin-left: 0;border: 1px solid #999;"></span>High</li>')
    f_report.write('<li style="font-size: 80%;list-style: none;margin-left: 0;line-height: 18px;margin-bottom: 2px;">')
    f_report.write('<span style="background:#8DD3C7;display: block; float: left;height: 16px;width: 30px;margin-right: 5px;margin-left: 0;border: 1px solid #999;"></span>No vulnerabilties</li></ul></div>')
    f_report.write('<br><br>')
    f_report.write('<table width="100%" style="margin: 0px;">')
    f_report.write('<tr>')
    f_report.write('<th> CVE Number </th>')
    f_report.write('<th> Vulnerable Dependency Name </th>')
    f_report.write('<th> Vulnerability Risk </th>')
    f_report.write('<th> Date of Creation </th>')
    f_report.write('<th> Summary </th>')
    f_report.write('</tr>')
    
    vul_count = 0
    low_vul = 0
    med_vul = 0
    high_vul = 0
    no_vul_pkg = 0
    vul_pkg = 0
    total_dep = len(proj_deps)
    
    for vul_dep, vul_details in proj_details.items():
        if len(vul_details) < 1:
            no_vul_pkg += 1
            row_color = "#8DD3C7"
            f_report.write('<tr '+'bgcolor="' + row_color + '">')
            f_report.write('<td>None</td>')
            f_report.write('<td>%s</td>' % vul_dep)
            f_report.write('<td>None</td>')
            f_report.write('<td>None</td>')
            f_report.write('<td>None</td>')
        else:
            vul_pkg += 1
        for vul in vul_details:
            vul_count += 1
            vul_risk = vul['Risk']
            if vul_risk.lower() == "low":
                row_color = "#FFFF00"
                low_vul += 1
            elif vul_risk.lower() == "medium":  
                row_color = "#FFA500"
                med_vul += 1
            else: 
                row_color = "#FF0000"
                high_vul += 1
                
            f_report.write('<tr '+'bgcolor="' + row_color + '">')
            f_report.write('<td>%s</td>' % vul['CVE'])
            f_report.write('<td>%s</td>' % vul_dep)
            f_report.write('<td>%s</td>' % vul['Risk'])
            f_report.write('<td>%s</td>' % vul['Date created'])
            f_report.write('<td>%s</td>' % vul['Title'])
            f_report.write('</tr>')
            
    f_report.write('</table>')
    f_report.write('<br>')
    
    # Vulnerability distribution graph
    f_report.write('<h3> Vulnerability Distribution </h3>')
    f_report.write('<p>Below is the vulnerabiltiy distribution graph of the project where we can see which dependencies are vulnerable and how much they contribute in making the project insecure.</p>')
    f_report.write('<div><img src = ' + VULN_GRAPH + ' alt ="cfg" align="middle" height="500px" width="700px">\n </div>')
    
    # Summary of the report
    f_report.write('<p style="font-weight: bold"proj_deps = get_proj_deps(reqs_loc)> Total no. of dependencies : ' + str(total_dep) + '</p>')
    f_report.write('<p> Count of vulnerable dependencies  : ' + str(vul_pkg) + '</p>')
    f_report.write('<p> Count of non vulnerable dependencies  : ' + str(no_vul_pkg) + '</p><br>')
    f_report.write('<p style="font-weight: bold"> Total vulnerabilties found : ' + str(vul_count) + '</p>')
    f_report.write('<p> Low level vulnerabilties : ' + str(low_vul) + '</p>')
    f_report.write('<p> Medium level vulnerabilties : ' + str(med_vul) + '</p>')
    f_report.write('<p> High level vulnerabilties : ' + str(high_vul) + '</p>')
    f_report.write('<br><br>')
    
    f_report.close()

    
if __name__ == '__main__':

    try:
        # Parse the command line arguments
        proj_path = parse_arguments()

        #Get requirements.txt file path
        reqs_loc = get_reqs_loc(proj_path)
        
        #Get all project dependencies
        proj_deps = get_proj_deps(reqs_loc)
        
        #Get all vulnerable dependencies
        proj_vuln = get_proj_vulns(proj_deps)
        
        #Filter out all the importatnt information for report generation
        proj_details = get_project_summary(proj_vuln)
        
        print("proj_details :: ",proj_details)
        #Draw vulnerability distribution graph
        draw_graph(proj_details)
        
        #Generate html report
        report = generate_report(proj_details, proj_deps)
        
    except:
        sys.exit(1)
       
    # Successfully performed the analysis
    sys.exit(0)     