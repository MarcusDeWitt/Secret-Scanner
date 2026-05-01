# Secret-Scanner

## Overview
This project gets user input and scans files or directories for hardcoded secrets like API Keys, Passwords, Tokens, and Private Keys.
It scans using regex tokens to find patterns inside the files.

## How it works
It begins getting the user input of a file or directory in the Command-line interface (CLI) and then begins scanning it to see if there are any matches that are in the known patterns. 
If it does discover any matches it displays where it found it, in what file, and the type of secret found. 
It also keeps an updated log of events that have taken place when the program is being used.
