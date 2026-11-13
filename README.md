## Cookie Scanner Project

High-level Process
1. Tech stack will use either Python/Playwright/Selenium or node.js/Playwright. Cookie scanning will primarily be done in one program by a headless browser like Playwright or Selenium.

2. Cookies will be detected by scanning browser storage and network apis. Cookies will have fields:
  - Name
  - Domain
  - Path
  - Expiration Date
  - Flags
  - Value
  - Maybe more

Domain will be most important in determining external tracking/third party cookies. Program must be able to be given a URL and exhaust other paths/pages to detect cookies there as well. We also want the ability to scan for cookies both before and after a user clicks a cookies disclosure to make sure cookies aren't collected before the user either accepts or denies.

3. Compare domain names with a data file (probably csv or json) which contains a list of harmful third party domains. We may come across more as we do the project which we can add as well. After comparing either print a report saying how many third party cookies a website has or some kind of UI with

*entities.JSON and services.JSON come from the disconnect-tracking-connection list of harmful domains/services (https://github.com/disconnectme/disconnect-tracking-protection/tree/master)

## Setup
1. In the terminal, `cd` into project directory
2. Create a virtual environment: `python -m venv venv`
3. Activate the virtual environment: `source venv/Scripts/activate`
4. Install requirements: `pip install -r requirements.txt`
5. Run the cookie scanner: `python scan.py`
6. Check the folder `cookie_reports` to see the json report of what was found in execution.

