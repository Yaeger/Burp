This is a Burp Extension to create log files.

Often times, I forget to create my Burp logs before I start crawling a web application. These logs can come in handy, so it's infuriating to crawl the application again to just get the logs.

Note: This currently only creates logs out of the Proxy tab.
Note: I have not yet added a button/context menu to trigger the extension. You must load the extension, and have the output/errors save to a file you choose.
Note: There isn't a method using Burp's API to get the request/response history for Repeater, Intruder yet.

Todo:

- Create logs for Scanner, Spider
- Create Menu tab to select which Tool (Scanner, Proxy, Spider) to save to logs.
- Create save as button in Menu tab



