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
package com.xwiki.ldapuserimport;

import java.util.Map;

import org.xwiki.component.annotation.Role;

/**
 * @version $Id$
 * @since 1.0
 */
@Role
public interface LDAPUserImportManager
{
    /**
     * Check if the current user has delete right on a topic: the user is the topic creator and the topic doesn't have
     * any answers created by other users and there aren't any other users' comments in the answers page OR the user has
     * delete right on current forum.
     * 
     * @param field the topic document
     * @param value the value
     * @return true of the conditions are met, false otherwise
     */

    Map<String, Map<String, String>> getUsers(String field, String value);
}
