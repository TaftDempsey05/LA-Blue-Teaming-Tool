# LA-Blue-Teaming-Tool
Creators: Taft Dempsey and Robert Florian

## Introduction
With any business that uses software where employees have to login to work, log analysis is a very important aspect to maintaining good cybersecurity standards. Log analysis is the practice of logging who logged into your system, what time they logged in, what they did when logged in, and when they logged out. This process should be done for every IP address and username. An industry that practices good log analysis skills is way more likely to detect unauthorized logins, suspicious activity(adding or deleting files), accounts logging in at suspicious dates and times, and it allows organizations to monitor what is going on on their systems. We hope our tool is useful to help organizations increase the speed and quality of their log analysis techniques since it is a very important aspect of cybersecurity that all organizations should follow.

## Solution 
We were able to create a large python program that has the tools needed to extract the important information from a log file and report it in a clean manner. Our python code extracts the important information and presents it in a PDF document where it includes sections that reports the login activity of each user, the activity and terminal commands each user did, and it marks possible suspicious activity like if a user logs in at a weird time. It also has the ability to scan for possible SQL injection attacks to see if an attacker was trying to bypass login credentials. We also wanted to give the report a visual feel too using the matplotlib python library. For example, we created graphs that mark how many times a user performed a certain action like logging in or performing a command. This will give users a visual representation of the activities each user performed in a given log file. One of the most important aspects of the report is the section that goes over the suspicious activity. For example, the project will report if it suspects a possible SQL injection attempt and/or a user logs in at an unusual time(like in the middle of the night on a weekend). This section will allow an organization’s cybersecurity team to start deeper investigations into the suspicious activity reported.

## Usage Steps

## Step 1: Install the requirements
In your LA-Blue-Teaming-Tool terminal, run the command "pip install requirements.txt" to install the required python libraries for the program to work. This will include numpy, keras, tensorflow, and matplotlib.

## Step 2: Run the program
In your same terminal, run the command "python main.py log_data.txt" to run the main python program on your log_data.txt file. 

## Step 3: Examine the results
You should now have a PDF document in your folder called analysis_report.pdf. Open it and examine the results of your log file.

## Trying different log files
Right now, our program is set to run on log files that follow the same format as the one we used for this project. Below is a sample line from our log file. All lines follow that same format with different information.

2026-02-12 09:22:02 user=admin src_ip=10.0.0.5 action=ls status=success

If you want to run this tool on a file with a slightly different format, you will have to change the parse_log_line function to meet the format of your file. This is optional, but you could also change and/or add to the known_users, suspicous times, and sql patterns to your liking based on what you want to python program to look for.
