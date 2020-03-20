# IssueHighlighter

IssueHighlighter is a BurpSuite extension that automatically highlights responses indicative of vulnerabilities or general issues in the history tab. The extension includes a growing list of configurable scan tools. See Tools list below. For example, IssueHighlighter includes a "Click Jacking" scan tool that looks for requests missing the "X-Frame-Options" header and highlights the response in the history tab. Note that this tool Highlight's responses that MIGHT indicate an issue, for example using "X-Frame-Options" headers is not the only way to prevent click jacking.

![Highlights in the Burp history tab](/docs/HistoryTab.png "Burp history tab")

The extension adds a new tab to BurbSuite that allows the user to disable/enable individual tools and set the color those tools use to highlight the responses.

![IssueHighlighter Tab](/docs/HighlighterTab.png "IssueHighlighter Tab")

## Tools List

### ClickJack Scanner
The ClickJack Scanner Highlights responses that meet the following criteria - 
* That don't have the "X-Frame-Options" header indicating the response might be Frameable 
* The response has a status code in the 200 range
* The response has a HTML or TEXT MIME type

_Note - This is not the only criteria for preventing or finding ClickJacking vulnerabilities._  

### Reflected UserAgent Scanner
This scanner looks for the user-agent string being reflected in the body of a response by pulling it out of the request header, then scanning the response body as it comes in.

_Note - A user Agent string being reelected is not a vulnerability by itself._


## Status Notes

This tool is still in beta and therefore not all of its functionality has been implemented.

* Currently the check box to disable or enable the scan tools is non-functional

* The Selected highlight color in the IssueHighlighter tab does not accurately display the color being used until a selection has been made.