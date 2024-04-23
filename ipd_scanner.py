import argparse
import os
import subprocess
import datetime
import logging
from xml.dom import minidom

"""
This script performs an IpDiscover scan on user provided subnets. 
The scan can be done using nmap or fping, depending on the options provided by the user.
The results are saved to a local xml file in the output directory.
"""
import xml.etree.ElementTree as ET

class IpdScanner:
    """
    Class to perform an IpDiscover scan on provided subnets.
    """

    def __init__(self, scantype, subnets, output_dir, debug=False):
        self.debug = debug
        self.setupLogging(debug)
        self.scantype = scantype
        self.subnets = subnets.split(',') if subnets else []
        self.output_dir = self.checkOutputDir(output_dir)
        self.logger.info(f"Starting IpDiscover scan with scantype: {self.scantype}, subnets: {self.subnets}, output_dir: {self.output_dir}")

    def setupLogging(self, debug):
        """Setup logging for the script."""
        # create logs directory if it does not exist
        if not os.path.exists("logs"):
            os.makedirs("logs")
        elif not os.access("logs", os.W_OK):
            print("Logs directory is not writable. Exiting.")
            exit(1)
        logging.basicConfig(level=logging.DEBUG if debug else logging.INFO, format='%(asctime)s - %(name)s - %(levelname)s - %(message)s', filename="logs/ipd_scanner.log")
        self.logger = logging.getLogger("IpdScanner")

    def checkOutputDir(self, output_dir):
        """Check if the output directory is valid and writable."""
        # default output dir is results/ if not provided by user
        if not output_dir:
            output_dir = "results/"
        else:
            # check that the output directory exists and is writable
            if not os.path.exists(output_dir):
                # fallback to default if directory does not exist
                self.logger.info(f"Output directory {output_dir} does not exist. Using default directory results/")
                output_dir = "results/"
            elif not os.access(output_dir, os.W_OK):
                self.logger.info(f"Output directory {output_dir} is not writable. Using default directory results/")
                output_dir = "results/"
        return output_dir
    
    def runCommand(self, command):
        """Run a shell command and return the output."""
        try:
            result = subprocess.run(command, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, universal_newlines=True)

            # special handling for fping
            if 'fping' in command:
                # log an error only if the return code is neither 0 (success) nor 1 (partial success)
                if result.returncode not in (0, 1):
                    self.logger.error(f"Command failed with return code {result.returncode}. Command: {command}")
            else:
                # for nmap
                if result.returncode != 0:
                    self.logger.error(f"Command failed with return code {result.returncode}. Command: {command}")
            
            return result.stdout
        except Exception as e:
            self.logger.error(f"Error running command: {command}. Exception: {str(e)}")
            return ""

    def parseNmapOutput(self, output, tag=''):
        """Parse the nmap output and return a list of dicts with ip, mac, hostname and tag."""
        results = []
        for line in output.splitlines():
            if "Nmap scan report for" in line:
                parts = line.split()
                ip = parts[-1].strip("()")
                results.append({'ip': ip, 'mac': '', 'hostname': '', 'tag': tag})
            elif "MAC Address:" in line:
                parts = line.split(" ", 2)
                if len(results) > 0:
                    results[-1]['mac'] = parts[2].split(" ")[0]
                # data inside () is the hostname, if equals anything else than 'Unknown' we keep it
                if "(" in parts[2]:
                    hostname = parts[2].split("(", 1)[1].split(")")[0]
                    results[-1]['hostname'] = hostname if hostname != "Unknown" else ""
            
        self.logger.debug(f"Results: {results}")
        return results

    def nmapScan(self, subnet, tag=''):
        """Run an nmap scan on the provided subnet and return the results."""
        command = f"nmap -sn {subnet}"
        self.logger.info(f"Running command: {command}")
        output = self.runCommand(command)
        self.logger.debug(f"Command output: {output}")
        return self.parseNmapOutput(output, tag)

    def fpingScan(self, subnet, tag=''):
        """Run an fping scan on the provided subnet and return the results."""
        command = f"fping -g --quiet -a {subnet}"
        self.logger.info(f"Running command: {command}")
        output = self.runCommand(command)
        self.logger.debug(f"Command output: {output}")
        results = [{'ip': line.strip(), 'mac': '', 'hostname': '', 'tag': tag} for line in output.splitlines() if line]
        return results
    
    def getDeviceId(self):
        """Generate a placeholder device id for the scan results."""
        deviceid = "IPDISCOVER-SCANNER"
        # add date (format : YYYY-MM-DD-HH-MM-SS)
        deviceid += "-" + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S")
        return deviceid

    def ipdScan(self):
        """Perform an IpDiscover scan on the provided subnets."""
        scanResults = []
        for subnet in self.subnets:
            # TAG is the substring after : in the subnet
            if ":" in subnet:
                tag = subnet.split(":")[1]
                subnet = subnet.split(":")[0]
            else:
                tag = ''

            self.logger.info(f"Scanning subnet {subnet}" + (f" with tag '{tag}'" if tag else "") + f" using {self.scantype}")
            if self.scantype == "nmap":
                scanResults += self.nmapScan(subnet, tag)
            elif self.scantype == "fping":
                scanResults += self.fpingScan(subnet, tag)

        self.generateXml(scanResults)

    def generateXml(self, scanResults):
        """Generate an XML file with the scan results."""
        self.logger.debug(f"Generating XML file for scan results : {scanResults}")
        root = ET.Element("REQUEST")
        content = ET.SubElement(root, "CONTENT")
        ipd = ET.SubElement(content, "IPDISCOVER")
        for result in scanResults:
            host = ET.SubElement(ipd, "H")
            ET.SubElement(host, "I").text = result['ip']
            ET.SubElement(host, "M").text = result.get('mac', 'Unknown')
            ET.SubElement(host, "N").text = result.get('hostname', 'Unknown')
            ET.SubElement(host, "T").text = result.get('tag', 'Unknown')

        # adding TAG
        net = ET.SubElement(content, "SUBNETS")
        for subnet in self.subnets:
            ET.SubElement(net, "S").text = subnet.split(":")[0]
        
        # query type and device id are mandatory and allow server to identify the request
        ET.SubElement(root, "QUERY").text = "IPDISCOVER"
        ET.SubElement(root, "DEVICEID").text = self.getDeviceId()

        xmlStr = minidom.parseString(ET.tostring(root)).toprettyxml(indent="   ")
        self.saveXml(xmlStr)
        self.logger.info("End of scan.")

    def saveXml(self, xmlData):
        """Save the XML data to a file."""
        # file name is datetime based
        filename = "ipdiscover-scan-" + datetime.datetime.now().strftime("%Y-%m-%d-%H-%M-%S") + ".xml"
        self.logger.debug(f"Saving XML data to file {self.output_dir + filename}")
        try:
            with open(self.output_dir + filename, "w") as file:
                file.write(xmlData)
            self.logger.info(f"Scan results saved to {self.output_dir + filename}")
        except Exception as e:
            self.logger.error(f"Error saving XML data to file {self.output_dir + filename}. Exception: {str(e)}")


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description=
                                     "Perform an IpDiscover scan on provided subnets, using nmap or fping. " +
                                     "The results will be saved to a local xml file in the output directory." +
                                        "The file is meant to be uploaded to an OCS server.")
    parser.add_argument('--scantype', help='Type of scan to perform: nmap or fping')
    parser.add_argument('--subnets', help='Subnets to scan, CIDR format, comma separated. Optionally, use : to add a tag to the subnet. Example: --subnets=172.18.25.0/24:net25')
    parser.add_argument('--output_dir', help='Directory to save the scan results')
    parser.add_argument('--debug', help='Enable debug mode', action='store_true')
    args = parser.parse_args()

    # if missing args
    if not args.scantype or not args.subnets:
        parser.print_help()
        exit(1)

    try:
        scanner = IpdScanner(args.scantype, args.subnets, args.output_dir, args.debug)
        scanner.ipdScan()
    except Exception as e:
        print(f"An error occurred: {str(e)}")
