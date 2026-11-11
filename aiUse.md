

Date: 11/11/26
Member: Justin
Agent: Claude 5.5 Sonnet
Prompt:
''' 
  I want to use selenium to make a cookie scanner and detector for harmful third party cookies, here is the code outline so far ##Cookie Scanner Project

  High-level Process
  1. Tech stack will use either Python/Playwright/Selenium or node.js/Playwright. Cookie scanning will primarily be done in one program by a headless browser like Playwright or Selenium.

      Cookies will be detected by scanning browser storage and network apis. Cookies will have fields:
          Name
          Domain
          Path
          Expiration Date
          Flags
          Value
          Maybe more

  Domain will be most important in determining external tracking/third party cookies. Program must be able to be given a URL and exhaust other paths/pages to detect cookies there as well. We also want the ability to scan for cookies both before and after a user clicks a cookies disclosure to make sure cookies aren't collected before the user either accepts or denies.

    Compare domain names with a data file (probably csv or json) which contains a list of harmful third party domains. We may come across more as we do the project which we can add as well. After comparing either print a report saying how many third party cookies a website has or some kind of UI with 
    
    I want a python script for scanning and need a good source for bad domains
'''

Output: 
The output was the first version of scan.py.