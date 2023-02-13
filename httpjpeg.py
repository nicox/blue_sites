from selenium import webdriver
from selenium.webdriver.firefox.firefox_binary import FirefoxBinary
from selenium.webdriver import FirefoxOptions


#driver = webdriver.PhantomJS()
opts = FirefoxOptions()
opts.add_argument("--headless")

driver = webdriver.Firefox(options=opts)
driver.set_window_size(1120, 550)
driver.get("http://192.168.1.13/")
print(driver.current_url)

driver.get_screenshot_as_file("/usr/local/src/security/data/http-screenshots/")
driver.quit()
