from burp import IBurpExtender, IContextMenuFactory, IHttpRequestResponse
from javax.swing import JMenuItem
from java.awt import Toolkit
from java.awt.datatransfer import StringSelection

class BurpExtender(IBurpExtender, IContextMenuFactory, IHttpRequestResponse):
    
    def registerExtenderCallbacks(self, callbacks):
        self._callbacks = callbacks
        self._helpers = callbacks.getHelpers()
        callbacks.setExtensionName("Copy as X8 Command")
        callbacks.registerContextMenuFactory(self)

    def createMenuItems(self, invocation):
        items = []
        if invocation.getInvocationContext() == invocation.CONTEXT_MESSAGE_EDITOR_REQUEST:
            item = JMenuItem("Copy as X8 Command", actionPerformed=lambda _: self.copyAsX8Command(invocation))
            items.append(item)
        return items

    def copyToClipboard(self, data):
        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        selection = StringSelection(data)
        clipboard.setContents(selection, None)

    def copyAsX8Command(self, invocation):
        http = invocation.getSelectedMessages()[0]
        request_str = self._helpers.bytesToString(http.getRequest())

        # Parse request line
        head = request_str.split('\r\n')[0]
        method = head.split()[0]

        # Parse URL
        url = http.getUrl().toString()

        # Parse headers
        raw_headers = request_str.split('\r\n\r\n')[0].split('\r\n')[1:]
        headers = []
        skip_list = ["Host", "Content-Length", "Connection", "Accept-Encoding", "Accept"]

        for h in raw_headers:
            if ":" not in h:
                continue
            k = h.split(":", 1)[0].strip()
            v = h.split(":", 1)[1].strip()
            if k in skip_list:
                continue
            
            # escape quotes
            k = k.replace("\\", "\\\\").replace("\"", "\\\"")
            v = v.replace("\\", "\\\\").replace("\"", "\\\"")

            headers.append('"{}: {}"'.format(k, v))

        # Parse body
        body = ""
        if "\r\n\r\n" in request_str:
            body = request_str.split("\r\n\r\n", 1)[1]
            body = body.replace("\\", "\\\\").replace("\"", "\\\"")

        # Build command
        cmd = 'x8 -u "{}" '.format(url.replace("\\", "\\\\").replace("\"", "\\\""))

        if method != "GET":
            cmd += '-X {} '.format(method)

        # Append single -H then all headers
        if headers:
            cmd += "-H " + " ".join(headers) + " "


        self.copyToClipboard(cmd)
