# -*- coding: utf-8 -*-
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

        valid_contexts = [
            invocation.CONTEXT_MESSAGE_EDITOR_REQUEST,
            invocation.CONTEXT_MESSAGE_VIEWER_REQUEST,
            invocation.CONTEXT_TARGET_SITE_MAP_TREE,
            invocation.CONTEXT_TARGET_SITE_MAP_TABLE,
            invocation.CONTEXT_PROXY_HISTORY,
        ]

        if invocation.getInvocationContext() in valid_contexts:

            selected = invocation.getSelectedMessages()

            if selected and len(selected) > 0:

                item = JMenuItem(
                    "Copy as X8 Command",
                    actionPerformed=lambda _: self.copyAsX8Command(invocation)
                )

                items.append(item)

        return items

    def copyToClipboard(self, data):

        clipboard = Toolkit.getDefaultToolkit().getSystemClipboard()
        clipboard.setContents(StringSelection(data), None)

    #
    # Safe POSIX quoting (Jython compatible)
    #
    def shell_quote(self, value):

        if value is None:
            return "''"

        value = str(value)

        if value == "":
            return "''"

        return "'" + value.replace("'", "'\"'\"'") + "'"

    def copyAsX8Command(self, invocation):

        messages = invocation.getSelectedMessages()

        if not messages:
            return

        http = messages[0]

        request_bytes = http.getRequest()
        request_info = self._helpers.analyzeRequest(http)
        request_str = self._helpers.bytesToString(request_bytes)

        #
        # METHOD + URL
        #
        method = request_info.getMethod()
        url = http.getUrl().toString()

        #
        # HEADERS
        #
        headers = []
        content_type = ""

        for h in request_info.getHeaders()[1:]:

            if ":" not in h:
                continue

            k, v = h.split(":", 1)
            k = k.strip()
            v = v.strip()

            if k.lower() == "content-type":
                content_type = v.lower()

            if k in [
                "Host",
                "Content-Length",
                "Connection",
                "Accept-Encoding",
                "Accept"
            ]:
                continue

            headers.append("{}: {}".format(k, v))

        #
        # BODY (FIXED SAFE LOGIC)
        #
        body = ""
        body_offset = request_info.getBodyOffset()

        if body_offset < len(request_bytes):

            body = request_str[body_offset:].strip()

            #
            # JSON handling → ONLY normalize
            #
            if "application/json" in content_type:

                try:
                    import json
                    parsed = json.loads(body)
                    body = json.dumps(parsed, separators=(",", ":"))
                except:
                    pass

            #
            # form-urlencoded → ONLY newline normalization
            #
            elif "application/x-www-form-urlencoded" in content_type:

                body = body.replace("\r\n", "&") \
                           .replace("\r", "&") \
                           .replace("\n", "&")

        #
        # BUILD COMMAND
        #
        cmd_parts = [
            "x8",
            "-u",
            self.shell_quote(url)
        ]

        if method and method != "GET":
            cmd_parts.extend([
                "-X",
                self.shell_quote(method)
            ])

        #
        # SINGLE -H ARG (x8 requirement)
        #
        if headers:

            combined_headers = "\\n".join(headers)

            cmd_parts.extend([
                "-H",
                self.shell_quote(combined_headers)
            ])

        #
        # BODY
        #
        if body:

            cmd_parts.extend([
                "-b",
                self.shell_quote(body)
            ])

        #
        # FINAL COMMAND
        #
        cmd = " ".join(cmd_parts)

        self.copyToClipboard(cmd)
