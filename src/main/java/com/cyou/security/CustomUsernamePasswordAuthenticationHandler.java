package com.cyou.security;

import org.apache.commons.lang3.BooleanUtils;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.math.NumberUtils;
import org.apereo.cas.adaptors.jdbc.AbstractJdbcUsernamePasswordAuthenticationHandler;
import org.apereo.cas.adaptors.jdbc.QueryDatabaseAuthenticationHandler;
import org.apereo.cas.authentication.AuthenticationHandlerExecutionResult;
import org.apereo.cas.authentication.Credential;
import org.apereo.cas.authentication.PreventedException;
import org.apereo.cas.authentication.UsernamePasswordCredential;
import org.apereo.cas.authentication.exceptions.AccountDisabledException;
import org.apereo.cas.authentication.exceptions.AccountPasswordMustChangeException;
import org.apereo.cas.authentication.handler.support.AbstractUsernamePasswordAuthenticationHandler;
import org.apereo.cas.authentication.principal.Principal;
import org.apereo.cas.authentication.principal.PrincipalFactory;
import org.apereo.cas.configuration.model.support.jdbc.QueryJdbcAuthenticationProperties;
import org.apereo.cas.configuration.support.JpaBeans;
import org.apereo.cas.services.ServicesManager;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.dao.DataAccessException;
import org.springframework.dao.IncorrectResultSizeDataAccessException;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.jdbc.core.namedparam.NamedParameterJdbcTemplate;

import javax.security.auth.login.AccountNotFoundException;
import javax.security.auth.login.FailedLoginException;
import javax.sql.DataSource;
import java.security.GeneralSecurityException;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class CustomUsernamePasswordAuthenticationHandler extends AbstractUsernamePasswordAuthenticationHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(CustomUsernamePasswordAuthenticationHandler.class);

    private JdbcTemplate jdbcTemplate;
    private QueryJdbcAuthenticationProperties queryJdbcAuthenticationProperties;

    public CustomUsernamePasswordAuthenticationHandler(String name, ServicesManager servicesManager, PrincipalFactory principalFactory, Integer order, QueryJdbcAuthenticationProperties queryJdbcAuthenticationProperties) {
        super(name, servicesManager, principalFactory, order);

        DataSource dataSource = JpaBeans.newDataSource(queryJdbcAuthenticationProperties);
        JdbcTemplate jdbcTemplate = new JdbcTemplate(dataSource);
        this.jdbcTemplate = jdbcTemplate;
        this.queryJdbcAuthenticationProperties = queryJdbcAuthenticationProperties;
    }

    @Override
    protected AuthenticationHandlerExecutionResult authenticateUsernamePasswordInternal(UsernamePasswordCredential credential, String originalPassword) throws GeneralSecurityException, PreventedException {
        String username = credential.getUsername();
        String password = credential.getPassword();

        List<Map<String, Object>> list = jdbcTemplate.queryForList(queryJdbcAuthenticationProperties.getSql(),new Object[]{username});
        if(list.size()==0) throw new AccountNotFoundException(username+" 不存在");

        Map<String, Object> dbFields = list.get(0);

        String dbPassword = dbFields.get(queryJdbcAuthenticationProperties.getFieldPassword()).toString();
        String salt = dbFields.get("salt").toString();
        String userpassword = PasswordUtil.encrypt(username, password, salt);
//
        if(userpassword.equals(dbPassword)){
            return createHandlerResult(credential,
                    this.principalFactory.createPrincipal(credential.getUsername()),
                    new ArrayList<>(0));
        }else{
            throw new AccountNotFoundException("密码不正确");
        }

    }

}
