/*
 * See the NOTICE file distributed with this work for additional
 * information regarding copyright ownership.
 *
 * This is free software; you can redistribute it and/or modify it
 * under the terms of the GNU Lesser General Public License as
 * published by the Free Software Foundation; either version 2.1 of
 * the License, or (at your option) any later version.
 *
 * This software is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this software; if not, write to the Free
 * Software Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA
 * 02110-1301 USA, or see the FSF site: http://www.fsf.org.
 */
package com.xwiki.ldapuserimport.script;

import java.util.Map;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Singleton;

import org.xwiki.component.annotation.Component;
import org.xwiki.script.service.ScriptService;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.xwiki.ldapuserimport.LDAPUserImportManager;

/**
 * @version $Id$
 * @since 1.0
 */
@Component
@Named("ldapuserimport")
@Singleton
public class LDAPUserImportScriptService implements ScriptService
{
    @Inject
    private LDAPUserImportManager manager;

    @Inject
    private ContextualAuthorizationManager contextualAuthorizationManager;

    /**
     * Returns a list of users based on the query.
     * 
     * @param field the string
     * @param value the value
     * @return a list of users
     */
    public Map<String, Map<String, String>> getUsers(String field, String value)
    {
        if (contextualAuthorizationManager.hasAccess(Right.EDIT)) {
            return manager.getUsers(field, value);
        }
        return null;
    }
}
