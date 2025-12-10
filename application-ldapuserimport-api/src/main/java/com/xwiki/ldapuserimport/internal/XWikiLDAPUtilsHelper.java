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
package com.xwiki.ldapuserimport.internal;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;

/**
 * Internal utility class to provide help methods to deal with LDAP queries.
 *
 * @version $Id$
 * @since 1.4
 */
public final class XWikiLDAPUtilsHelper
{
    /**
     * LDAP UID.
     */
    public static final String UID = "uid";

    /**
     * LDAP CN.
     */
    public static final String CN = "cn";

    /**
     * Configuration key used in the LDAP Authenticator to define the base DN for LDAP searches.
     */
    public static final String LDAP_BASE_DN = "ldap_base_DN";

    private static final String OR_FILTER_STARTING_MARK = "(|";

    private static final String AND_FILTER_STARTING_MARK = "(&";

    private static final String FILTER_ENDING_MARK = ")";

    private static final String LDAP_GROUP_CLASSES_KEY = "ldap_group_classes";

    private static final String LDAP_GROUP_SEARCH_FIELDS_KEY = "ldap_group_searchfields";

    private static final String LDAP_USER_CLASSES_KEY = "ldap_user_classes";

    private static final String LDAP_GROUP_CLASSES = "group,groupOfNames,groupOfUniqueNames,dynamicGroup,"
        + "dynamicGroupAux,groupWiseDistributionList,posixGroup,apple-group";

    private static final String LDAP_GROUP_SEARCH_FIELDS = CN;

    private static final String LDAP_USER_CLASSES = "*";

    private XWikiLDAPUtilsHelper()
    {

    }

    /**
     * Method to retrieve the Users Filter to search for users in LDAP.
     * Filter pattern for contains search:
     * (&(|(objectClass={1A})(objectClass={1B}))(|({2}=*{3}*)({4}=*{5}*)({6}=*{7}*)...)).
     * Filter pattern for begins with search:
     * (&(|(objectClass={1A})(objectClass={1B}))(|({2}={3}*)({4}={5}*)({6}={7}*)...)).
     *
     * @param searchInput the value to search for
     * @param searchFields a comma-separated list of fields to search for
     * @param configuration the current LDAP configuration
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @return the filter
     */
    public static String getUsersFilter(String searchInput, String searchFields,
        XWikiLDAPConfig configuration, boolean isFullSearch)
    {
        return getUsersFilter(searchInput, searchFields.split(XWikiLDAPConfig.DEFAULT_SEPARATOR),
            configuration, isFullSearch);
    }

    /**
     * Method to retrieve a Filter for objectClasses.
     *
     * @param objectClassesString A comma separated list of LDAP objectClasses
     * @return the filter
     **/
    public static String getFilterFromObjectClasses(String objectClassesString)
    {
        String[] objectClasses = objectClassesString.split(XWikiLDAPConfig.DEFAULT_SEPARATOR);

        StringBuilder filter = new StringBuilder();
        filter.append(OR_FILTER_STARTING_MARK);
        for (String objectClass : objectClasses) {
            filter.append(String.format("(objectClass=%s)", objectClass));
        }
        filter.append(FILTER_ENDING_MARK);
        return filter.toString();
    }

    /**
     * Method to retrieve the Search Filter to search for users or groups in LDAP.
     *
     * @param objectClassesString A comma separated list of LDAP objectClasses
     * @param searchInput the value to search for
     * @param searchFields a comma-separated list of fields to search for
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @return the filter
     **/
    public static String getSearchFilter(String objectClassesString, String searchInput, String[] searchFields,
        boolean isFullSearch)
    {
        String filterFormat = "(%s=%s*)";
        if (isFullSearch) {
            filterFormat = "(%s=*%s*)";
        }

        String objectClassesFilter = getFilterFromObjectClasses(objectClassesString);
        StringBuilder filter = new StringBuilder(AND_FILTER_STARTING_MARK);

        filter.append(OR_FILTER_STARTING_MARK);
        for (String field : searchFields) {
            filter.append(String.format(filterFormat,
                XWikiLDAPConnection.escapeLDAPSearchFilter(field),
                XWikiLDAPConnection.escapeLDAPSearchFilter(searchInput)));
        }
        filter.append(FILTER_ENDING_MARK);

        filter.append(objectClassesFilter);
        filter.append(FILTER_ENDING_MARK);
        return filter.toString();
    }

    /**
     * Method to get the filter to search for users in LDAP.
     *
     * @param searchInput the value to search for
     * @param searchFields the list of fields to search for
     * @param configuration the current LDAP configuration
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @return the filter
     */
    public static String getUsersFilter(String searchInput, String[] searchFields,
        XWikiLDAPConfig configuration, boolean isFullSearch)
    {
        String objectClassesString = configuration.getLDAPParam(LDAP_USER_CLASSES_KEY, LDAP_USER_CLASSES);
        return getSearchFilter(objectClassesString, searchInput, searchFields, isFullSearch);
    }

    /**
     * Method to get the filter to search for groups in LDAP.
     *
     * @param searchInput the input to search for
     * @param configuration the current LDAP configuration
     * @param isFullSearch allowing to choose if the search is a "contains" search or a "begin with" search
     * @return the group filter according to the pattern
     */
    public static String getGroupsFilter(String searchInput, XWikiLDAPConfig configuration, boolean isFullSearch)
    {
        String objectClassesString = configuration.getLDAPParam(LDAP_GROUP_CLASSES_KEY, LDAP_GROUP_CLASSES);
        String searchFields = configuration.getLDAPParam(LDAP_GROUP_SEARCH_FIELDS_KEY, LDAP_GROUP_SEARCH_FIELDS);
        return getSearchFilter(objectClassesString, searchInput,
            searchFields.split(XWikiLDAPConfig.DEFAULT_SEPARATOR), isFullSearch);
    }

    /**
     * Create a map of user field mapping from the given LDAP configuration.
     *
     * @param configuration the current LDAP configuration
     * @param defaultMapping the default mapping
     * @return the user field mapping
     */
    public static Map<String, String> getUserFieldsMap(XWikiLDAPConfig configuration,
        Map<String, String> defaultMapping)
    {
        Map<String, String> fieldsMap = new HashMap<>();

        // Make sure to add the UID field, since it may not be present in the LDAP fields mapping.
        String uidFieldName = configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UID, CN);
        fieldsMap.put(uidFieldName, UID);

        // Make sure to also add all the mapped fields.
        fieldsMap.putAll(configuration.getUserMappings(null));

        // Make sure to also add all the default LDAP fields mappings. LDAP configuration could provide only few of
        // them, but for display purposes, we need them all.
        for (Map.Entry<String, String> pair : defaultMapping.entrySet()) {
            fieldsMap.putIfAbsent(pair.getKey(), pair.getValue());
        }

        return fieldsMap;
    }

    /**
     * Get a list of user attributes to be searched for.
     *
     * @param configuration the LDAP configuration
     * @param defaultMapping the default mapping to use when constructing the list
     * @return a list of user attributes to be searched for
     */
    public static String[] getUserAttributes(XWikiLDAPConfig configuration, Map<String, String> defaultMapping)
    {
        Set<String> attributes = new HashSet<>();

        // Make sure to add the UID field, to get its value in the PagedLDAPSearchResult.
        String uidFieldName = configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UID, CN);
        attributes.add(uidFieldName);

        // Make sure to also add all the mapped fields, to get their values in the PagedLDAPSearchResult.
        List<String> userAttributes = new ArrayList<>();
        configuration.getUserMappings(userAttributes);
        attributes.addAll(userAttributes);

        // Also append the LDAP photo attribute if synchronization of LDAP profile pictures is enabled
        if (configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_UPDATE_PHOTO, "0").equals("1")) {
            attributes.add(configuration.getLDAPParam(XWikiLDAPConfig.PREF_LDAP_PHOTO_ATTRIBUTE,
                XWikiLDAPConfig.DEFAULT_PHOTO_ATTRIBUTE));
        }

        // Make sure to also add all the default LDAP fields mappings. LDAP configuration could provide only few of
        // them, but for display purposes, we need them all.
        for (Map.Entry<String, String> pair : defaultMapping.entrySet()) {
            attributes.add(pair.getValue());
        }

        return attributes.toArray(new String[attributes.size()]);
    }
}
