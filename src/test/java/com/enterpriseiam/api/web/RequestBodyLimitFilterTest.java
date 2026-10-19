package com.enterpriseiam.api.web;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.Mockito.*;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

import com.enterpriseiam.api.auth.AuthController;
import com.enterpriseiam.api.auth.TokenResponseMapper;
import com.enterpriseiam.security.auth.AuthenticationService;
import com.enterpriseiam.security.web.SecurityExceptionHandler;
import com.enterpriseiam.security.web.SecurityProblemSupport;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.FilterChain;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletRequestWrapper;
import java.io.IOException;
import java.io.OutputStream;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.atomic.AtomicLong;
import org.junit.jupiter.api.Test;
import org.mapstruct.factory.Mappers;
import org.springframework.http.HttpHeaders;
import org.springframework.http.MediaType;
import org.springframework.http.converter.json.MappingJackson2HttpMessageConverter;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.test.web.servlet.MockMvc;
import org.springframework.test.web.servlet.setup.MockMvcBuilders;

class RequestBodyLimitFilterTest {
    private final ObjectMapper mapper = new ObjectMapper()
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS);
    private final SecurityProblemSupport problems = new SecurityProblemSupport(mapper);
    private final RequestBodyLimitFilter filter = new RequestBodyLimitFilter(problems);

    @Test
    void knownOversizedAuthenticationBodyIsRejectedWithoutReadingOrInvokingChain() throws Exception {
        MockHttpServletRequest request = request("POST", "/api/v1/auth/login",
                new byte[(int) RequestBodyLimitFilter.AUTH_BODY_LIMIT + 1]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        assertProblem413(response);
        verifyNoInteractions(chain);
    }

    @Test
    void chunkedBodyCrossingLimitInBulkReadReturns413WithoutUnboundedBuffering() throws Exception {
        MockHttpServletRequest raw = request("POST", "/api/v1/auth/refresh",
                new byte[(int) RequestBodyLimitFilter.AUTH_BODY_LIMIT + 1024]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(raw, -1), response,
                (request, ignored) -> request.getInputStream().transferTo(OutputStream.nullOutputStream()));
        assertProblem413(response);
    }

    @Test
    void dishonestContentLengthCannotBypassActualBytesLimit() throws Exception {
        MockHttpServletRequest raw = request("POST", "/api/v1/auth/login",
                new byte[(int) RequestBodyLimitFilter.AUTH_BODY_LIMIT + 1]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(raw, 1), response,
                (request, ignored) -> request.getInputStream().transferTo(OutputStream.nullOutputStream()));
        assertProblem413(response);
    }

    @Test
    void exactLimitBodyCanBeReadToEof() throws Exception {
        MockHttpServletRequest raw = request("POST", "/api/v1/auth/login",
                new byte[(int) RequestBodyLimitFilter.AUTH_BODY_LIMIT]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        AtomicLong bytes = new AtomicLong();
        filter.doFilter(withReportedLength(raw, -1), response,
                (request, ignored) -> bytes.set(request.getInputStream().transferTo(OutputStream.nullOutputStream())));
        assertThat(bytes.get()).isEqualTo(RequestBodyLimitFilter.AUTH_BODY_LIMIT);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void singleByteReadsAndReaderAccessCannotBypassLimit() throws Exception {
        byte[] body = new byte[(int) RequestBodyLimitFilter.AUTH_BODY_LIMIT + 1];
        MockHttpServletResponse bytesResponse = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(request("POST", "/api/v1/auth/login", body), -1), bytesResponse,
                (request, ignored) -> {
                    while (request.getInputStream().read() != -1) { }
                });
        assertProblem413(bytesResponse);
        MockHttpServletResponse readerResponse = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(request("POST", "/api/v1/auth/login", body), -1), readerResponse,
                (request, ignored) -> {
                    while (request.getReader().read() != -1) { }
                });
        assertProblem413(readerResponse);
    }

    @Test
    void resourceLimitPermitsWorstCaseEscapedContentButRejectsLargerKnownBody() throws Exception {
        MockHttpServletRequest request = request("PUT", "/api/v1/resources/123", new byte[0]);
        FilterChain chain = mock(FilterChain.class);
        MockHttpServletResponse allowed = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(request, RequestBodyLimitFilter.RESOURCE_BODY_LIMIT), allowed, chain);
        verify(chain).doFilter(any(HttpServletRequest.class), same(allowed));
        clearInvocations(chain);
        MockHttpServletResponse rejected = new MockHttpServletResponse();
        filter.doFilter(withReportedLength(request, RequestBodyLimitFilter.RESOURCE_BODY_LIMIT + 1), rejected, chain);
        assertProblem413(rejected);
        verifyNoInteractions(chain);
    }

    @Test
    void unrelatedRequestsArePassedThroughWithoutWrappingOrReading() throws Exception {
        MockHttpServletRequest request = request("GET", "/api/v1/resources/123", new byte[0]);
        MockHttpServletResponse response = new MockHttpServletResponse();
        FilterChain chain = mock(FilterChain.class);
        filter.doFilter(request, response, chain);
        verify(chain).doFilter(same(request), same(response));
    }

    @Test
    void wrappedJacksonOverflowMapsTo413AndNeverInvokesAuthentication() throws Exception {
        AuthenticationService authentication = mock(AuthenticationService.class);
        MockMvc mvc = loginMvc(authentication);
        byte[] body = ("{\"email\":\"user@example.test\",\"password\":\""
                + "x".repeat((int) RequestBodyLimitFilter.AUTH_BODY_LIMIT) + "\"}").getBytes(StandardCharsets.UTF_8);
        mvc.perform(servletContext -> {
                    MockHttpServletRequest request = new MockHttpServletRequest(servletContext) {
                        @Override public long getContentLengthLong() { return -1; }
                        @Override public int getContentLength() { return -1; }
                    };
                    request.setMethod("POST");
                    request.setRequestURI("/api/v1/auth/login");
                    request.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    request.setContent(body);
                    return request;
                })
                .andExpect(status().isPayloadTooLarge())
                .andExpect(content().contentType(MediaType.APPLICATION_PROBLEM_JSON))
                .andExpect(jsonPath("$.status").value(413));
        verifyNoInteractions(authentication);
    }

    @Test
    void oversizedChunkedWhitespaceAfterJsonIsRejectedBeforeAuthentication() throws Exception {
        AuthenticationService authentication = mock(AuthenticationService.class);
        MockMvc mvc = loginMvc(authentication);
        byte[] body = ("{\"email\":\"user@example.test\",\"password\":\"secret\"}"
                + " ".repeat((int) RequestBodyLimitFilter.AUTH_BODY_LIMIT)).getBytes(StandardCharsets.UTF_8);
        mvc.perform(servletContext -> {
                    MockHttpServletRequest request = new MockHttpServletRequest(servletContext) {
                        @Override public long getContentLengthLong() { return -1; }
                        @Override public int getContentLength() { return -1; }
                    };
                    request.setMethod("POST");
                    request.setRequestURI("/api/v1/auth/login");
                    request.setContentType(MediaType.APPLICATION_JSON_VALUE);
                    request.setContent(body);
                    return request;
                })
                .andExpect(status().isPayloadTooLarge()).andExpect(jsonPath("$.status").value(413));
        verifyNoInteractions(authentication);
    }

    private MockMvc loginMvc(AuthenticationService authentication) {
        return MockMvcBuilders.standaloneSetup(new AuthController(authentication,
                        Mappers.getMapper(TokenResponseMapper.class)))
                .setControllerAdvice(new SecurityExceptionHandler(problems))
                .setMessageConverters(new MappingJackson2HttpMessageConverter(mapper))
                .addFilter(filter).build();
    }

    private static MockHttpServletRequest request(String method, String path, byte[] content) {
        MockHttpServletRequest request = new MockHttpServletRequest(method, path);
        request.setContentType(MediaType.APPLICATION_JSON_VALUE);
        request.setContent(content);
        return request;
    }

    private static HttpServletRequest withReportedLength(HttpServletRequest request, long reported) {
        return new HttpServletRequestWrapper(request) {
            @Override public long getContentLengthLong() { return reported; }
            @Override public int getContentLength() { return (int) reported; }
        };
    }

    private void assertProblem413(MockHttpServletResponse response) throws IOException {
        assertThat(response.getStatus()).isEqualTo(413);
        assertThat(response.getContentType()).isEqualTo(MediaType.APPLICATION_PROBLEM_JSON_VALUE);
        assertThat(response.getHeader(HttpHeaders.CACHE_CONTROL)).isEqualTo("no-store");
        assertThat(response.getHeader(HttpHeaders.PRAGMA)).isEqualTo("no-cache");
        assertThat(mapper.readTree(response.getContentAsByteArray()).get("status").asInt()).isEqualTo(413);
    }
}
