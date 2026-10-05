package com.kiwicaptcha.servlet;

import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.Cookie;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.servlet.http.HttpSession;
import jakarta.servlet.http.Part;
import jakarta.servlet.http.HttpUpgradeHandler;
import jakarta.servlet.http.PushBuilder;

import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.Principal;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;

/**
 * A hand-rolled servlet harness for the filter tests: no spring-test
 * or container dependency, just the two interfaces the filter reads.
 */
public final class MockHttp {
    private MockHttp() {}

    public static final class Request implements HttpServletRequest {
        private final String method;
        private final String uri;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private final Map<String, String> parameters = new LinkedHashMap<>();
        private final Map<String, Object> attributes = new HashMap<>();
        private String remoteAddr;
        private byte[] body = new byte[0];
        private String contentType = "";
        private boolean readerConsumed;

        public Request(String method, String uri) {
            this.method = method;
            this.uri = uri;
            this.remoteAddr = "127.0.0.1";
        }

        public Request header(String name, String value) {
            headers.put(name.toLowerCase(Locale.ROOT), value);
            return this;
        }

        public Request parameter(String name, String value) {
            parameters.put(name, value);
            return this;
        }

        public Request formBody(Map<String, String> form) {
            StringBuilder sb = new StringBuilder();
            for (Map.Entry<String, String> entry : form.entrySet()) {
                if (sb.length() > 0) {
                    sb.append('&');
                }
                sb.append(java.net.URLEncoder.encode(entry.getKey(), StandardCharsets.UTF_8))
                        .append('=')
                        .append(java.net.URLEncoder.encode(entry.getValue(), StandardCharsets.UTF_8));
            }
            this.body = sb.toString().getBytes(StandardCharsets.UTF_8);
            this.contentType = "application/x-www-form-urlencoded";
            return this;
        }

        public Request remoteAddr(String value) {
            this.remoteAddr = value;
            return this;
        }

        @Override
        public String getMethod() {
            return method;
        }

        @Override
        public String getRequestURI() {
            return uri;
        }

        @Override
        public String getHeader(String name) {
            return headers.get(name.toLowerCase(Locale.ROOT));
        }

        @Override
        public Enumeration<String> getHeaderNames() {
            return Collections.enumeration(headers.keySet());
        }

        @Override
        public String getContentType() {
            return contentType;
        }

        @Override
        public String getParameter(String name) {
            return parameters.get(name);
        }

        @Override
        public Map<String, String[]> getParameterMap() {
            Map<String, String[]> out = new HashMap<>();
            for (Map.Entry<String, String> entry : parameters.entrySet()) {
                out.put(entry.getKey(), new String[]{entry.getValue()});
            }
            return out;
        }

        @Override
        public Enumeration<String> getParameterNames() {
            return Collections.enumeration(parameters.keySet());
        }

        @Override
        public String[] getParameterValues(String name) {
            String value = parameters.get(name);
            return value == null ? null : new String[]{value};
        }

        @Override
        public String getRemoteAddr() {
            return remoteAddr;
        }

        @Override
        public Object getAttribute(String name) {
            return attributes.get(name);
        }

        @Override
        public void setAttribute(String name, Object value) {
            attributes.put(name, value);
        }

        @Override
        public BufferedReader getReader() {
            readerConsumed = true;
            return new BufferedReader(new java.io.InputStreamReader(
                    new ByteArrayInputStream(body), StandardCharsets.UTF_8));
        }

        @Override
        public ServletInputStream getInputStream() {
            ByteArrayInputStream backing = new ByteArrayInputStream(body);
            return new ServletInputStream() {
                @Override
                public boolean isFinished() {
                    return backing.available() == 0;
                }

                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setReadListener(ReadListener listener) {
                    // Synchronous harness.
                }

                @Override
                public int read() {
                    return backing.read();
                }
            };
        }

        @Override
        public String getCharacterEncoding() {
            return StandardCharsets.UTF_8.name();
        }

        // Unused harness surface: the filter never touches these.
        @Override public String getAuthType() { return null; }
        @Override public Cookie[] getCookies() { return new Cookie[0]; }
        @Override public long getDateHeader(String name) { return -1; }
        @Override public Enumeration<String> getHeaders(String name) { return Collections.emptyEnumeration(); }
        @Override public int getIntHeader(String name) { return -1; }
        @Override public String getPathInfo() { return null; }
        @Override public String getPathTranslated() { return null; }
        @Override public String getContextPath() { return ""; }
        @Override public String getQueryString() { return null; }
        @Override public String getRemoteUser() { return null; }
        @Override public boolean isUserInRole(String role) { return false; }
        @Override public Principal getUserPrincipal() { return null; }
        @Override public String getRequestedSessionId() { return null; }
        @Override public StringBuffer getRequestURL() { return new StringBuffer(uri); }
        @Override public String getServletPath() { return uri; }
        @Override public HttpSession getSession(boolean create) { return null; }
        @Override public HttpSession getSession() { return null; }
        @Override public String changeSessionId() { return null; }
        @Override public boolean isRequestedSessionIdValid() { return false; }
        @Override public boolean isRequestedSessionIdFromCookie() { return false; }
        @Override public boolean isRequestedSessionIdFromURL() { return false; }
        @Override public boolean authenticate(HttpServletResponse response) { return false; }
        @Override public void login(String username, String password) {}
        @Override public void logout() {}
        @Override public Collection<Part> getParts() { return List.of(); }
        @Override public Part getPart(String name) { return null; }
        @Override public <T extends HttpUpgradeHandler> T upgrade(Class<T> handlerClass) { return null; }
        @Override public PushBuilder newPushBuilder() { return null; }
        @Override public void setCharacterEncoding(String env) throws UnsupportedEncodingException {}
        @Override public Enumeration<String> getAttributeNames() { return Collections.enumeration(attributes.keySet()); }
        @Override public void removeAttribute(String name) {}
        @Override public Locale getLocale() { return Locale.ROOT; }
        @Override public Enumeration<Locale> getLocales() { return Collections.enumeration(List.of(Locale.ROOT)); }
        @Override public boolean isSecure() { return false; }
        @Override public jakarta.servlet.RequestDispatcher getRequestDispatcher(String path) { return null; }
        @Override public int getRemotePort() { return 0; }
        @Override public String getRemoteHost() { return remoteAddr; }
        @Override public String getLocalAddr() { return "127.0.0.1"; }
        @Override public String getLocalName() { return "localhost"; }
        @Override public int getLocalPort() { return 0; }
        @Override public String getServerName() { return "localhost"; }
        @Override public int getServerPort() { return 80; }
        @Override public String getProtocol() { return "HTTP/1.1"; }
        @Override public String getScheme() { return "http"; }
        @Override public jakarta.servlet.ServletConnection getServletConnection() { return null; }
        @Override public String getProtocolRequestId() { return ""; }
        @Override public String getRequestId() { return "1"; }
        @Override public jakarta.servlet.DispatcherType getDispatcherType() { return jakarta.servlet.DispatcherType.REQUEST; }
        @Override public jakarta.servlet.ServletContext getServletContext() { return null; }
        @Override public jakarta.servlet.AsyncContext startAsync() { return null; }
        @Override public jakarta.servlet.AsyncContext startAsync(jakarta.servlet.ServletRequest request, jakarta.servlet.ServletResponse response) { return null; }
        @Override public boolean isAsyncStarted() { return false; }
        @Override public jakarta.servlet.AsyncContext getAsyncContext() { return null; }
        @Override public int getContentLength() { return body.length; }
        @Override public long getContentLengthLong() { return body.length; }
        @Override public boolean isAsyncSupported() { return false; }
    }

    public static final class Response implements HttpServletResponse {
        private int status = 200;
        private final Map<String, String> headers = new LinkedHashMap<>();
        private final StringBuilder body = new StringBuilder();
        private String contentType;

        public int status() {
            return status;
        }

        public String body() {
            return body.toString();
        }

        @Override
        public void setStatus(int sc) {
            this.status = sc;
        }

        @Override
        public void setContentType(String type) {
            this.contentType = type;
            this.headers.put("content-type", type);
        }

        @Override
        public java.io.PrintWriter getWriter() {
            return new java.io.PrintWriter(new java.io.Writer() {
                @Override
                public void write(char[] cbuf, int off, int len) {
                    body.append(cbuf, off, len);
                }

                @Override
                public void flush() {
                    // The harness body is written through immediately.
                }

                @Override
                public void close() {
                    // Nothing to release.
                }
            }, true);
        }

        // Unused harness surface.
        @Override public void sendError(int sc) {}
        @Override public void sendError(int sc, String msg) {}
        @Override
        public void sendRedirect(String location) {
            setHeader("Location", location);
            setStatus(302);
        }
        @Override public void setHeader(String name, String value) { headers.put(name.toLowerCase(Locale.ROOT), value); }
        @Override public void addHeader(String name, String value) {}
        @Override public void setDateHeader(String name, long date) {}
        @Override public void addDateHeader(String name, long date) {}
        @Override public void setIntHeader(String name, int value) {}
        @Override public void addIntHeader(String name, int value) {}
        @Override public String getHeader(String name) { return headers.get(name.toLowerCase(Locale.ROOT)); }
        @Override public Collection<String> getHeaders(String name) { return List.of(); }
        @Override public Collection<String> getHeaderNames() { return headers.keySet(); }
        @Override public boolean containsHeader(String name) { return headers.containsKey(name.toLowerCase(Locale.ROOT)); }
        @Override public void addCookie(Cookie cookie) {}
        @Override public String encodeURL(String url) { return url; }
        @Override public String encodeRedirectURL(String url) { return url; }
        @Override public void setContentLength(int len) {}
        @Override public void setContentLengthLong(long len) {}
        @Override public jakarta.servlet.ServletOutputStream getOutputStream() {
            return new jakarta.servlet.ServletOutputStream() {
                @Override
                public boolean isReady() {
                    return true;
                }

                @Override
                public void setWriteListener(jakarta.servlet.WriteListener listener) {
                    // Synchronous harness.
                }

                @Override
                public void write(int b) {
                    body.append((char) b);
                }
            };
        }
        @Override public void setCharacterEncoding(String charset) {}
        @Override public String getCharacterEncoding() { return "UTF-8"; }
        @Override public void setBufferSize(int size) {}
        @Override public int getBufferSize() { return 0; }
        @Override public void flushBuffer() {}
        @Override public void resetBuffer() {}
        @Override public void reset() {}
        @Override public boolean isCommitted() { return false; }
        @Override public Locale getLocale() { return Locale.ROOT; }
        @Override public void setLocale(Locale locale) {}
        @Override public int getStatus() { return status; }
        @Override public String getContentType() { return contentType; }
    }
}
