package com.enterpriseiam.api.web;

import com.enterpriseiam.security.web.SecurityProblemSupport;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ReadListener;
import jakarta.servlet.ServletException;
import jakarta.servlet.ServletInputStream;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import jakarta.servlet.http.HttpServletResponse;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.util.Objects;
import org.springframework.http.HttpStatus;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;
import org.springframework.web.util.UrlPathHelper;

/**
 * Bounds JSON while it is consumed, including chunked requests without Content-Length. The wrapper
 * allocates no body buffer. Ingress limits remain useful for connections and bodies nobody consumes.
 */
@Component
public final class RequestBodyLimitFilter extends OncePerRequestFilter {
    static final long AUTH_BODY_LIMIT = 16 * 1024;
    // Every UTF-16 code unit accepted by the domain can occupy six bytes as a JSON unicode escape.
    static final long RESOURCE_BODY_LIMIT = 6L * 1_048_576 + 1024;
    private final SecurityProblemSupport problems;

    public RequestBodyLimitFilter(SecurityProblemSupport problems) {
        this.problems = problems;
    }

    @Override
    protected boolean shouldNotFilter(HttpServletRequest request) {
        return bodyLimit(request) == 0;
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request, HttpServletResponse response, FilterChain chain)
            throws ServletException, IOException {
        long limit = bodyLimit(request);
        if (request.getContentLengthLong() > limit) {
            problems.write(request, response, HttpStatus.PAYLOAD_TOO_LARGE);
            return;
        }
        try {
            chain.doFilter(new LimitedRequest(request, limit), response);
        } catch (IOException | ServletException failure) {
            if (!RequestBodyTooLargeException.causedBy(failure)) {
                throw failure;
            }
            problems.write(request, response, HttpStatus.PAYLOAD_TOO_LARGE);
        }
    }

    private static long bodyLimit(HttpServletRequest request) {
        String path = UrlPathHelper.defaultInstance.getPathWithinApplication(request);
        if ("POST".equals(request.getMethod()) && path.startsWith("/api/v1/auth/")) {
            return AUTH_BODY_LIMIT;
        }
        if ("PUT".equals(request.getMethod()) && path.startsWith("/api/v1/resources/")) {
            return RESOURCE_BODY_LIMIT;
        }
        return 0;
    }

    private static final class LimitedRequest extends HttpServletRequestWrapper {
        private final long limit;
        private ServletInputStream stream;
        private BufferedReader reader;
        private boolean streamRequested;

        private LimitedRequest(HttpServletRequest request, long limit) {
            super(request);
            this.limit = limit;
        }

        @Override
        public ServletInputStream getInputStream() throws IOException {
            if (reader != null) {
                throw new IllegalStateException("getReader has already been called for this request");
            }
            streamRequested = true;
            return limitedStream();
        }

        @Override
        public BufferedReader getReader() throws IOException {
            if (streamRequested) {
                throw new IllegalStateException("getInputStream has already been called for this request");
            }
            if (reader == null) {
                Charset charset = getCharacterEncoding() == null ? StandardCharsets.UTF_8
                        : Charset.forName(getCharacterEncoding());
                reader = new BufferedReader(new InputStreamReader(limitedStream(), charset));
            }
            return reader;
        }

        private ServletInputStream limitedStream() throws IOException {
            if (stream == null) {
                stream = new LimitedInputStream(super.getInputStream(), limit);
            }
            return stream;
        }
    }

    private static final class LimitedInputStream extends ServletInputStream {
        private final ServletInputStream delegate;
        private final long limit;
        private long consumed;

        private LimitedInputStream(ServletInputStream delegate, long limit) {
            this.delegate = delegate;
            this.limit = limit;
        }

        @Override
        public int read() throws IOException {
            ensureWithinLimit();
            int value = delegate.read();
            if (value != -1) {
                count(1);
            }
            return value;
        }

        @Override
        public int read(byte[] bytes, int offset, int length) throws IOException {
            Objects.checkFromIndexSize(offset, length, bytes.length);
            if (length == 0) {
                return 0;
            }
            ensureWithinLimit();
            // One extra byte distinguishes an exact-limit EOF from a body exceeding the limit.
            int requested = (int) Math.min(length, Math.max(1, limit - consumed + 1));
            int count = delegate.read(bytes, offset, requested);
            if (count > 0) {
                count(count);
            }
            return count;
        }

        private void count(int bytes) throws RequestBodyTooLargeException {
            consumed += bytes;
            ensureWithinLimit();
        }

        private void ensureWithinLimit() throws RequestBodyTooLargeException {
            if (consumed > limit) {
                throw new RequestBodyTooLargeException();
            }
        }

        @Override public boolean isFinished() { return delegate.isFinished(); }
        @Override public boolean isReady() { return delegate.isReady(); }
        @Override public void setReadListener(ReadListener listener) { delegate.setReadListener(listener); }
        @Override public void close() throws IOException { delegate.close(); }
        @Override public int available() throws IOException {
            return (int) Math.min(delegate.available(), Math.max(0, limit - consumed));
        }
    }
}
