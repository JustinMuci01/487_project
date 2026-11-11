from selenium import webdriver
import time

driver = webdriver.Chrome()

try:
    driver.get("https://www.google.com/")
    print(driver.title)
    time.sleep(10)
finally:
    driver.quit()