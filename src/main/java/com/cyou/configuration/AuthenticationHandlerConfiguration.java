package com.cyou.configuration;

import com.cyou.security.CustomAbstractJdbcUsernamePasswordAuthenticationHandler;
import com.cyou.security.CustomQueryDatabaseAuthenticationHandler;
import com.cyou.security.CustomUsernamePasswordAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryDatabaseAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlan;
import org.apereo.cas.authentication.AuthenticationEventExecutionPlanConfigurer;
import org.apereo.cas.authentication.AuthenticationHandler;
import org.apereo.cas.authentication.principal.DefaultPrincipalFactory;
import org.apereo.cas.configuration.CasConfigurationProperties;
import org.apereo.cas.configuration.model.support.jdbc.JdbcAuthenticationProperties;
import org.apereo.cas.configuration.model.support.jdbc.QueryJdbcAuthenticationProperties;
import org.apereo.cas.configuration.support.JpaBeans;
import org.apereo.cas.services.ServicesManager;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.beans.factory.annotation.Qualifier;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.jdbc.core.JdbcTemplate;

import javax.sql.DataSource;
import java.util.Collection;
import java.util.Iterator;

@Configuration
public class AuthenticationHandlerConfiguration implements AuthenticationEventExecutionPlanConfigurer {

    @Autowired
    @Qualifier("servicesManager")
    private ServicesManager servicesManager;
    
//    @Autowired
//    @Qualifier("jdbcAuthenticationHandlers")
//    private Collection<AuthenticationHandler> jdbcAuthenticationHandlers;
    @Autowired
    private CasConfigurationProperties casProperties;

    @Bean
    public AuthenticationHandler customAuthenticationHandler() {
//        Collection<AuthenticationHandler> jdbcAuthenticationHandlers = this.jdbcAuthenticationHandlers;
//        System.out.println(jdbcAuthenticationHandlers);
//        Iterator<AuthenticationHandler> iterator = jdbcAuthenticationHandlers.iterator();
//        for (AuthenticationHandler authenticationHandler: jdbcAuthenticationHandlers) {
//            if(authenticationHandler instanceof QueryDatabaseAuthenticationHandler){
//                QueryDatabaseAuthenticationHandler queryDatabaseAuthenticationHandler = (QueryDatabaseAuthenticationHandler)authenticationHandler;
//                System.out.println(queryDatabaseAuthenticationHandler);
//
//            }
//        }

        JdbcAuthenticationProperties jdbc = this.casProperties.getAuthn().getJdbc();

        QueryJdbcAuthenticationProperties queryJdbcAuthenticationProperties = jdbc.getQuery().get(0);

        CustomUsernamePasswordAuthenticationHandler handler
                = new CustomUsernamePasswordAuthenticationHandler(
                        CustomUsernamePasswordAuthenticationHandler.class.getSimpleName(),
                        servicesManager, new DefaultPrincipalFactory(), 1,queryJdbcAuthenticationProperties);
        return handler;
    }

    @Override
    public void configureAuthenticationExecutionPlan(AuthenticationEventExecutionPlan plan) {
        plan.registerAuthenticationHandler(customAuthenticationHandler());
    }
}
