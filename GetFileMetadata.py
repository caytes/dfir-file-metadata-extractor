"""
Name: Ceslee Aytes
Date: 2020/12/16
Version: Python 3.7
Script: GetFileMetadata.py
Purpose: Retrieve System Information, IP Address, File Metadata, & Permissions from a Windows machine

The GetFileMetadata.py script builds onto the Week 4 Lab file (forensicFileRecorder.py). 
This script is useful in DFIR as it can automate extracting System Information,
the Local IP address, File Metadata, and File Permissions

Input Parameters: -path [directory] or -h [help]

Functions: GetUserInput, ValidatePath, WriteInformation, Main

"""

#Import modules
import os
import platform
import time
import sys
import csv
import argparse 
import socket
from prettytable import PrettyTable

# Retrieve and validate user input. Accepts "-path [directory]" and "-h"
def GetUserInput():
    # Command Line Arguments
    parser = argparse.ArgumentParser('Select an argument.')
    parser.add_argument('-path', dest='path', help='the input directory', required=True)
    args = parser.parse_args()
    path = os.path.abspath(args.path)
    ValidatePath(path)
    return path

# Checks if the directory exists. If not, throws an exception error. 
def ValidatePath(theDir):
    if os.path.exists(theDir):
        print('The directory exists. Please wait... \n')
        return True
    sys.exit('The directory does not exist.\nPlease input "-path (a valid directory)" or "-h" for help. \n')
    
# Retrieves System Info, Local IP Address, File Metadata, and Permissions
# Prints to PrettyTable and outputs to a CSV files
def WriteInformation(path):
    # Retrieve System Info and Local IP Address 
    hostname = socket.gethostname()
    hostIP = socket.gethostbyname(hostname)
    architecture = platform.machine()
    operatingSystem = platform.platform()
    processor = platform.processor()
    # System Info list
    systemInfo = [hostname, hostIP, architecture, operatingSystem, processor]  
    
    # CSV and PrettyTable headers
    fields = ['Filename', 'File Extension', 'Size (Bytes)', 'Owner ID', 'Group ID', 'Modified Time', 
              'Access Time', 'Creation Time', 'Read Access', 'Write Access', 'Execute Acess', 'Explicit Path']
    details = ['Hostname', 'Local IP', 'Architecture', 'OS', 'Processor']
      
    # Print System Info PrettyTable
    pTable2 = PrettyTable(details)
    pTable2.add_row(systemInfo)
    print(pTable2)
    print('\n')
    
    # Use hostname as base CSV filename
    csvF = str(hostname + '-FileReport.csv')
    
    # Try to open and write file information to the CSV file
    try:
        with open(csvF, 'w', newline='') as csvFile:                                    
            # Initialize csvwriter
            csvwriter = csv.writer(csvFile)   
            
            # Write System Info & Local IP address to CSV file
            csvwriter.writerow(details)
            csvwriter.writerow(systemInfo)
            csvwriter.writerow('\n')
            
            # Create field header for prettytable and csvwriter 
            csvwriter.writerow(fields)
            pTable = PrettyTable(fields)    
            
            # Iterate through the directory to print File Metadata      
            print("Files in directory '%s': " % path + '\n')
            with os.scandir(path) as iterate:
                for entry in iterate:
                    if not entry.name.startswith('.'):
                        filename = os.path.basename(entry)                        
                        fileExtension = os.path.splitext(entry)[1]
                        fileSize = str(os.path.getsize(entry))                          
                        ownerId = str(os.stat(entry).st_uid)
                        groupID = str(os.stat(entry).st_gid)
                        modTime = time.ctime(os.path.getmtime(entry))
                        accessTime = time.ctime(os.path.getatime(entry))
                        creationTime = time.ctime(os.path.getctime(entry))
                        readAccess = str(os.access(entry, os.R_OK))
                        writeAccess = str(os.access(entry, os.W_OK))
                        executeAccess = str(os.access(entry, os.X_OK))
                        explicitPath = os.path.abspath(entry)                          
                    
                    # PrettyTable - Add rows
                    rows = [filename, fileExtension, fileSize, ownerId, groupID, modTime, accessTime, 
                            creationTime, readAccess, writeAccess, executeAccess, explicitPath]
                    pTable.add_row(rows)                
                    
                    # Write the rows to the CSV file
                    csvwriter.writerow(rows)
                    
            # Print the PrettyTable with File Metadata
            print(pTable) 
            
            # Print successful CSV creation
            print('\n The '+ csvF +' file created successfully! \n')
    
        # Close the CSV file
        csvFile.close()        
    
    # CSV creation error  
    except Exception as err:
        print("Failed: CSV File Save: ", str(err))


# Main function
def main():

    # Script header
    print('--+--+-- ' + 'SYSTEM INFO AND FILE METADATA EXTRACTOR' + ' --+--+--')
    print('Input is a folder.')
    print('Instruction Parameters: -path [directory] or -h [help]' + '\n')
    
    # Retrieve & validate user input
    validatedPath = GetUserInput()
    
    # Output all information to CSV file and PrettyTable
    WriteInformation(validatedPath)


# Main Function
if __name__ == "__main__":
    main()