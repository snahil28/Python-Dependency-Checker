

# Implementation

The tool is implemented keeping in mind the Secure Software Devlopment Life Cycle(S-SDLC) that tries to address the Security phase right from the very beginning of the development process of a project and doesn't include it as some later stage in the cycle as identifying security issues earlier in the development life cycle reduces cost and rework.

The detection approach of this tool in finding out any third party vulnerabilities in a project is code centric and it relies upon searching the code base for dependencies or libraries and then figuring out what might be vulnerable in these. A python based project has its third party dependencies required for its installation listed out in the 'requirements.txt' file and so it just need to search for this file in the code base and read from it all the dependencies and their versions. It doesn't need to wait for the project to compile or build or install to start with its analysis. 

If this tool is hooked into the development environment let's say in a build plugin, or just as an extension in the IDE that runs at regular intervals then everytime a developer does any programming it will monitor all the third party packages that are being imported and generates its report periodically. It's beneficial to the development team as developers can use this tool to know if they might be using some outdated dependency, or some vulnerable package for which a CVE was recently created. This all analysis and fixing can be done within the development stage itself and not postponing it to the later stages of testing or deployment. Once the tool finds any vulnerability that is in some package, developers will be notified (depending upon how the tool is scheduled to run) and they don't have to start over with the development phase or revert and rework and then again wait for the project to go in build, deployment or testing phase to test their changes. 

Consider a case where we are performing this analysis task at some later stages of SDLC (let's say the tool runs whenever a build is triggered or when an application is being deployed on some testing environment) and say the project is not often being updated but it's still deployed, then we might miss the notification here when a CVE just gets released for any package. In order to solve this probelm, we need to schedule this task before any build or deployment phase and need to run it in regular time intervals for eg. after every 24 hrs or so.

To use this solution for large dozens or hundreds of code repositories this process can be automated and can be included in CI/CD pipeline as an additional task in build system for e.g. Jenkins, where we can add this tool in a task that is scheduled to run after every 24 hrs and generate reports, this report can then be mailed to the development team or can be shared on the slack group. Furthermore, this tool can be enhanced by not only just looking into the 'requirments.txt' file but also going through the entire code base to fetch all the dependencies from *.egg, *.whl, *,zip and *.py files and extract not only the direct dependencies but also the entire chain of dependencies for thorough analysis. This can be done after the project has built so that it's deployable and contain all the packages that needs to be installed to make the project under analysis run successfully. Also as the code base might be very large, depending upon external database like Vuldb is not reliable as it'll be making an enormous no. of requests to htese databases. Also the tool won't work if the website is down, so here local database should be maintained. It should get its data from various databases like NVD or CVE Mitre and their should be a job that is scheduled to run and update this local database daily. Doing so ensures that we are keeping track of the latest vulnerabilities and updates and the project isn't using any vulnerable direct or indirect dependency.
                        
                        
# Functioning 

This tool analyzes all the third aprty dependencies of a Python based project that are listed in its 'requirements.txt' file and can be installed using Pip (Python Package Installer).

This tool performs the above operations in the following steps, 

1. It takes as input a path argument that points to the location of project on th local machine.

2. Then it collects all the project dependencies by reading the file 'requirements.txt' and makes a table consisting of the names of all the dependencies with their versions as specified in the file.

3. It then sends a request to PyPI (https://pypi.python.org/pypi/) to get the latest version of the package available.

4. It then constructs and shows up a table consisting of all the dependencies found, their installed versions as mentioned in the project's requirement file and the latest version availble in order to tell the developers which all packages should be upgraded.

3. For each dependency discovered in step 2, it sends a request to Vuldb, an online database documentation of security vulnerabilities and exploits to check if there are any publicly known and disclosed vulnerabilities associated with the package. 

4. It parses all the received results and filter out all the vulnerabilites associated with its package version number. The details of the vulnerability includes the dependency or the package name where the issue is found, its associated CVE number (Common Vulnerability Exposure), date of creation of the CVE, risk level of the vulnerability, and summary describing the vulnerability of the package.

5. It then shows a vulnerability ditribution graph showing us all the dependencies that are vulnerable and how much does it contribute in making the project insecure. Also it tells us the number of vulnerabilities and dependencies found, each in High, Medium and Low risk vulnerability category.
                        
                        
# Usage 

The tool can be used as an extension in the IDE or a build system and can be scheduled to run once in a day to track down all the outdated packages and any recent CVEs affecting any of the project dependecies. This can also be integrated as a task in Github or any other version control system and can thus become a part of Continuous Integration and Delivery pipeline (CI/CD pipeline) so whenever a developer pushes some code or make a pull request, it triggers this task and performs vulnerability analysis of the project. It can be integrated with the build system say Jenkins, where it can be scheduled to run after every 24 hrs, this will help us to track down all the vulnerabilities in a project that is not updated very often.

To use the tool, we have to run following commands - 

source app-env // to add the api_key to the environment variables
python dependency_checker.py <Path of the project source code directory> // this starts the analysis part of the tool

You can try '--help' or '--h' option to explore the help and how to run the tool against any project.

The tool should be tested in a container to ensure security as this provides a safe and secure way to test and validate the functioning of the tool without impacting the user's system and its environment. It'll download and install just the exact requirments with latest versions required to run this tool.
