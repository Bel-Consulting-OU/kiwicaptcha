package com.kiwicaptcha.spring;

import com.kiwicaptcha.Verifier;
import com.kiwicaptcha.servlet.KiwiCaptchaFilter;
import org.springframework.boot.autoconfigure.AutoConfiguration;
import org.springframework.boot.autoconfigure.condition.ConditionalOnClass;
import org.springframework.boot.autoconfigure.condition.ConditionalOnMissingBean;
import org.springframework.boot.autoconfigure.condition.ConditionalOnProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.web.servlet.FilterRegistrationBean;
import org.springframework.context.annotation.Bean;

import jakarta.servlet.Filter;

/**
 * The Spring Boot auto-configuration: one shared verifier built from
 * the kiwicaptcha.* properties and the Jakarta auto-verify filter
 * registered on the configured url patterns. A controller that wants
 * handler-mapping verification registers the KiwiTokenInterceptor
 * itself; the starter never forces both layers. Every bean is backed
 * off when the deployment defines its own.
 */
@AutoConfiguration
@ConditionalOnClass(Filter.class)
@ConditionalOnProperty(prefix = "kiwicaptcha", name = "secret")
@EnableConfigurationProperties(KiwiCaptchaProperties.class)
public class KiwiCaptchaAutoConfiguration {

    /** Builds the deployment verifier from the properties. */
    @Bean
    @ConditionalOnMissingBean(Verifier.class)
    public Verifier kiwiVerifier(KiwiCaptchaProperties properties) {
        return properties.buildVerifier();
    }

    /** Registers the auto-verify servlet filter on the configured patterns. */
    @Bean
    @ConditionalOnMissingBean(KiwiCaptchaFilter.class)
    public FilterRegistrationBean<KiwiCaptchaFilter> kiwiCaptchaFilter(Verifier verifier,
                                                                       KiwiCaptchaProperties properties) {
        KiwiCaptchaFilter filter = new KiwiCaptchaFilter(verifier, properties.getSecret(),
                properties.getExpectedScope(), null, properties.getTrustedProxies(), null);
        FilterRegistrationBean<KiwiCaptchaFilter> registration = new FilterRegistrationBean<>(filter);
        registration.setUrlPatterns(properties.getUrlPatterns());
        registration.setOrder(1);
        return registration;
    }
}
