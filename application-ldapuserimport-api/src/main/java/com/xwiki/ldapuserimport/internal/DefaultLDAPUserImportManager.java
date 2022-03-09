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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.SortedMap;
import java.util.TreeMap;
import java.util.stream.Collectors;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;
import javax.inject.Singleton;

import org.apache.commons.lang3.StringUtils;
import org.slf4j.Logger;
import org.xwiki.component.annotation.Component;
import org.xwiki.component.manager.ComponentLookupException;
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.ldap.PagedLDAPSearchResults;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPReferralException;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xwiki.ldapuserimport.LDAPUserImportManager;

/**
 * @version $Id$
 * @since 2.6
 */
@Component
@Singleton
public class DefaultLDAPUserImportManager implements LDAPUserImportManager
{
    private static final String MEMBER = "member";

    private static final String XWIKI_PREFERENCES = "XWikiPreferences";

    private static final String ACTIVE_DIRECTORY_HINT = "activedirectory";

    private static final String LDAP_GROUP_CLASSES_KEY = "ldap_group_classes";

    private static final String FILTER_CLOSING_MARK = "))";

    private static final String LDAP_GROUP_CLASSES = "group,groupOfNames,groupOfUniqueNames,dynamicGroup,"
        + "dynamicGroupAux,groupWiseDistributionList,posixGroup,apple-group";

    private static final String USERNAME = "username";

    private static final String LDAP_FIELDS_MAPPING = "ldap_fields_mapping";

    private static final String DEFAULT_LDAP_FIELDS_MAPPING = "first_name=givenName,last_name=sn,email=mail";

    private static final String UID = "uid";

    private static final String USER_PROFILE_KEY = "userProfile";

    private static final String USER_PROFILE_URL_KEY = "userProfileURL";

    private static final String EQUAL_STRING = "=";

    private static final String MAIN_WIKI_NAME = "xwiki";

    private static final String LDAP_USER_IMPORT = "LDAPUserImport";

    private static final String FIELDS_SEPARATOR = ",";

    private static final String XWIKI = "XWiki";

    private static final LocalDocumentReference PREFERENCES_REFERENCE =
        new LocalDocumentReference(XWIKI, XWIKI_PREFERENCES);

    private static final DocumentReference GLOBAL_PREFERENCES =
        new DocumentReference(MAIN_WIKI_NAME, XWIKI, XWIKI_PREFERENCES);

    private static final String LDAP_UID_ATTR = "ldap_UID_attr";

    private static final String LDAP_BASE_DN = "ldap_base_DN";

    private static final String CN = "cn";

    private static final String FAILED_TO_GET_RESULTS = "Failed to get results";

    private static final DocumentReference OIDC_CLASS =
        new DocumentReference(MAIN_WIKI_NAME, Arrays.asList(XWIKI, "OIDC"), "UserClass");

    private static final LocalDocumentReference GROUP_CLASS_REFERENCE =
        new LocalDocumentReference(XWIKI, "XWikiGroups");

    private static final LocalDocumentReference CONFIGURATION_REFERENCE =
        new LocalDocumentReference(LDAP_USER_IMPORT, "WebHome");

    private static final LocalDocumentReference CONFIGURATION_CLASS_REFERENCE =
        new LocalDocumentReference(LDAP_USER_IMPORT, "LDAPUserImportConfigClass");

    @Inject
    private ConfigurationSource configurationSource;

    @Inject
    @Named("context")
    private Provider<ComponentManager> componentManagerProvider;

    @Inject
    private ContextualAuthorizationManager contextualAuthorizationManager;

    @Inject
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @Inject
    private Logger logger;

    @Inject
    private Provider<XWikiContext> contextProvider;

    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     */
    @Override
    public Map<String, Map<String, String>> getUsers(String singleField, String allFields, String searchInput)
        throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        String loginDN = configuration.getLDAPBindDN();
        String password = configuration.getLDAPBindPassword();

        try {
            connection.open(loginDN, password, context);
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String[] attributeNameTable = getAttributeNameTable(configuration);

            String filter;
            if (StringUtils.isNoneBlank(singleField)) {
                filter = getUsersFilter(searchInput, singleField);
            } else if (StringUtils.isNoneBlank(allFields)) {
                filter = getUsersFilter(searchInput, allFields);
            } else {
                filter = getUsersFilter(searchInput, String.join(FIELDS_SEPARATOR, attributeNameTable));
            }

            PagedLDAPSearchResults result =
                connection.searchPaginated(base, LDAPConnection.SCOPE_SUB, filter, attributeNameTable, false);
            if (result.hasMore()) {
                return getUsers(configuration, connection, result, context);
            } else {
                logger.warn("There are no result for base dn: [{}], search scope: [{}], filter: [{}], fields: [{}]",
                    base, LDAPConnection.SCOPE_SUB, filter, attributeNameTable);
            }
        } catch (XWikiLDAPException e) {
            logger.error(e.getFullMessage());
            throw e;
        } catch (Exception e) {
            logger.warn("Failed to search for value [{}] in the fields [{}]", searchInput, allFields, e);
            throw e;
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
        return Collections.emptyMap();
    }

    private XWikiLDAPConfig getConfiguration() throws Exception
    {
        XWikiLDAPConfig configuration = new XWikiLDAPConfig(null, getConfigurationSource());
        setPageNameFormatter(configuration);
        if (StringUtils.isBlank(configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null))) {
            configuration.setFinalProperty(LDAP_FIELDS_MAPPING, DEFAULT_LDAP_FIELDS_MAPPING);
        }
        return configuration;
    }

    private Map<String, String> getFieldsMap(XWikiLDAPConfig configuration)
    {
        Map<String, String> fieldsMap = new HashMap<>();

        // Make sure to add the UID field, since it may not be present in the LDAP fields mapping.
        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        fieldsMap.put(uidFieldName, UID);

        // Make sure to also add all the mapped fields.
        for (String pair : configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null).split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            fieldsMap.put(parts[1], parts[0]);
        }

        // Make sure to also add all the default LDAP fields mappings. LDAP configuration could provide only few of
        // them, but for display purposes, we need them all.
        for (String pair : DEFAULT_LDAP_FIELDS_MAPPING.split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            if (!fieldsMap.containsKey(parts[1])) {
                fieldsMap.put(parts[1], parts[0]);
            }
        }
        return fieldsMap;
    }

    private String[] getAttributeNameTable(XWikiLDAPConfig configuration)
    {
        Set<String> attributesNameTable = new HashSet<>();

        // Make sure to add the UID field, to get its value in the PagedLDAPSearchResult.
        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        attributesNameTable.add(uidFieldName);

        // Make sure to also add all the mapped fields, to get their values in the PagedLDAPSearchResult.
        for (String pair : configuration.getLDAPParam(LDAP_FIELDS_MAPPING, null).split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            attributesNameTable.add(parts[1]);
        }

        // Make sure to also add all the default LDAP fields mappings. LDAP configuration could provide only few of
        // them, but for display purposes, we need them all.
        for (String pair : DEFAULT_LDAP_FIELDS_MAPPING.split(FIELDS_SEPARATOR)) {
            String[] parts = pair.split(EQUAL_STRING);
            // From first_name=givenName, store key=givenName and value=first_name.
            if (!attributesNameTable.contains(parts[1])) {
                attributesNameTable.add(parts[1]);
            }
        }
        return attributesNameTable.toArray(new String[attributesNameTable.size()]);
    }

    /**
     * Filter pattern: (&({0}={1})(|({2}=*{3}*)({4}=*{5}*)({6}=*{7}*)...)).
     */
    private String getUsersFilter(String searchInput, String searchFields)
    {
        StringBuilder filter = new StringBuilder("(&(objectClass=*)(|");
        for (String filed : Arrays.asList(searchFields.split(FIELDS_SEPARATOR))) {
            filter.append(String.format("(%s=*%s*)", XWikiLDAPConnection.escapeLDAPSearchFilter(filed),
                XWikiLDAPConnection.escapeLDAPSearchFilter(searchInput)));
        }
        filter.append(FILTER_CLOSING_MARK);
        return filter.toString();
    }

    /**
     * Filter pattern: (&(cn=*{0}*)(|(objectClass=class1)(objectClass=class2)...(objectClass=classN))).
     */
    private String getGroupsFilter(String searchInput, String objectClasses)
    {
        StringBuilder filter =
            new StringBuilder(String.format("(&(cn=*%s*)(|", XWikiLDAPConnection.escapeLDAPSearchFilter(searchInput)));
        for (String objectClass : objectClasses.split(FIELDS_SEPARATOR)) {
            filter.append(String.format("(objectClass=%s)", objectClass));
        }
        filter.append(FILTER_CLOSING_MARK);
        return filter.toString();
    }

    private Map<String, Map<String, String>> getUsers(XWikiLDAPConfig configuration, XWikiLDAPConnection connection,
        PagedLDAPSearchResults result, XWikiContext context) throws Exception
    {
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
        String uidFieldName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        ldapUtils.setUidAttributeName(uidFieldName);
        ldapUtils.setBaseDN(configuration.getLDAPParam(LDAP_BASE_DN, ""));
        LDAPEntry resultEntry = null;

        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                Map<String, String> fieldsMap = getFieldsMap(configuration);
                int maxDisplayedUsersNb = getMaxDisplayedUsersNb();
                boolean hasMore;
                Map<String, Map<String, String>> usersMap = new HashMap<>();
                do {
                    Map<String, String> user =
                        getUserDetails(connection, fieldsMap, ldapUtils, context, uidFieldName, resultEntry);
                    if (!user.isEmpty()) {
                        usersMap.put(user.get(UID), user);
                    }
                    hasMore = result.hasMore();
                    resultEntry = hasMore ? result.next() : null;
                } while (resultEntry != null && usersMap.size() < maxDisplayedUsersNb);
                // Only do the sorting on the UI side when we have less results than the limit or exactly the limit.
                // hasMore is false when usersMap.size() <= maxDisplayedUsersNb.
                if (!hasMore) {
                    SortedMap<String, Map<String, String>> sortedUsersMap = new TreeMap<>();
                    for (String userId : usersMap.keySet()) {
                        sortedUsersMap.put(userId, usersMap.get(userId));
                    }
                    return sortedUsersMap;
                }
                return usersMap;
            } else {
                /*
                 * For some weird reason result.hasMore() can be true before the first call to next() even if nothing is
                 * found.
                 */
                logger.warn("The LDAP request returned no result (hasMore() is true but first next() call "
                    + "returned nothing)");
            }
        } catch (Exception e) {
            logger.warn(FAILED_TO_GET_RESULTS, e);
            if (e instanceof LDAPReferralException) {
                logger.warn(((LDAPReferralException) e).getFailedReferral());
            }
            throw e;
        }
        return Collections.emptyMap();
    }

    /**
     * @return the maximum number of users to be displayed in the import wizard
     * @throws XWikiException
     */
    private int getMaxDisplayedUsersNb() throws Exception
    {
        int resultsNumber = getLDAPImportConfiguration().getIntValue("resultsNumber");
        if (resultsNumber == 0) {
            resultsNumber = 20;
        }
        return resultsNumber;
    }

    private Map<String, String> getUserDetails(XWikiLDAPConnection connection, Map<String, String> fieldsMap,
        XWikiLDAPUtils ldapUtils, XWikiContext context, String uidFieldName, LDAPEntry resultEntry)
    {
        String uidFieldValue = getAttributeValue(uidFieldName, resultEntry);
        if (StringUtils.isNoneBlank(uidFieldValue)) {
            List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
            connection.ldapToXWikiAttribute(searchAttributeList, resultEntry.getAttributeSet());
            String userPageName = ldapUtils.getUserPageName(searchAttributeList, context);
            DocumentReference userReference = new DocumentReference(MAIN_WIKI_NAME, XWIKI, userPageName);
            return getUserDetails(fieldsMap, searchAttributeList, userReference, context);
        }
        return Collections.emptyMap();
    }

    private Map<String, String> getUserDetails(Map<String, String> fieldsMap, List<XWikiLDAPSearchAttribute> attributes,
        DocumentReference userReference, XWikiContext context)
    {
        Map<String, String> user = new HashMap<>();
        boolean userExists = context.getWiki().exists(userReference, context);
        if (userExists) {
            user.put(USER_PROFILE_URL_KEY, context.getWiki().getURL(userReference, context));
        }
        user.put(USER_PROFILE_KEY, userReference.toString());
        user.put(USERNAME, userReference.getName());
        user.put("exists", Boolean.toString(userExists));

        for (XWikiLDAPSearchAttribute attribute : attributes) {
            String value = attribute.value;
            String name = attribute.name;
            if (fieldsMap.containsKey(name)) {
                user.put(fieldsMap.get(name), value);
            } else {
                user.put(name, value);
            }
        }
        return user;
    }

    private String getAttributeValue(String fieldName, LDAPEntry resultEntry)
    {
        String value = "";
        if (resultEntry.getAttribute(fieldName) != null) {
            value = resultEntry.getAttribute(fieldName).getStringValue();
        }
        return value;
    }

    @Override
    public Map<String, Map<String, String>> importUsers(String[] usersList, String groupName) throws Exception
    {
        if (usersList.length > 0) {
            XWikiContext context = contextProvider.get();
            String currentWikiId = context.getWikiId();
            // Make sure to use the main wiki configuration source.
            context.setWikiId(context.getMainXWiki());

            XWikiLDAPConfig configuration = getConfiguration();
            XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
            XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
            ldapUtils.setUidAttributeName(configuration.getLDAPParam(LDAP_UID_ATTR, CN));
            ldapUtils.setBaseDN(configuration.getLDAPParam(LDAP_BASE_DN, ""));

            try {
                connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);

                SortedMap<String, Map<String, String>> users = new TreeMap<>();

                String[] attributeNameTable = getAttributeNameTable(configuration);
                Map<String, String> fieldsMap = getFieldsMap(configuration);
                for (String user : usersList) {
                    List<XWikiLDAPSearchAttribute> attributes =
                        ldapUtils.searchUserAttributesByUid(user, attributeNameTable);
                    XWikiDocument userDoc =
                        ldapUtils.syncUser(null, attributes, ldapUtils.searchUserDNByUid(user), user, context);

                    // Make sure to get the latest version of the document, after LDAP synchronization.
                    userDoc = context.getWiki().getDocument(userDoc.getDocumentReference(), context);
                    addOIDCObject(userDoc, user, context);

                    Map<String, String> userMap =
                        getUserDetails(fieldsMap, attributes, userDoc.getDocumentReference(), context);

                    users.put(user, userMap);
                }
                addUsersInGroup(groupName, users);

                return users;
            } catch (XWikiException e) {
                logger.error(e.getFullMessage());
                throw e;
            } finally {
                connection.close();
                context.setWikiId(currentWikiId);
            }
        }
        return Collections.emptyMap();
    }

    private void setPageNameFormatter(XWikiLDAPConfig configuration) throws Exception
    {
        String pageNameFormatter = getLDAPImportConfiguration().getStringValue("pageNameFormatter");
        if (StringUtils.isNoneBlank(pageNameFormatter)) {
            configuration.setFinalProperty("ldap_userPageName", pageNameFormatter);
        }
    }

    private BaseObject getLDAPImportConfiguration() throws XWikiException
    {
        XWikiContext context = contextProvider.get();
        XWikiDocument importConfigDoc;
        try {
            importConfigDoc = context.getWiki().getDocument(CONFIGURATION_REFERENCE, context);
            BaseObject importConfigObj = importConfigDoc.getXObject(CONFIGURATION_CLASS_REFERENCE);
            return importConfigObj;
        } catch (XWikiException e) {
            logger.warn("Failed to get LDAP Import configuration document [{}].", CONFIGURATION_REFERENCE, e);
            throw e;
        }
    }

    /**
     * This method handles the creation of the XWiki.OIDC.UserClass object in user profile. The subject property should
     * be populated according to a mapping between the LDAP user attribute and OIDC subject format. The default mapping
     * is (OIDC) subject = (LDAP) uid. Example: if the LDAP uid is sAMAccountName, then the value from this field will
     * be stored in the OIDC subject. TODO: Provide flexibility to accept other field/formatter for the mapping.
     * 
     * @param userDoc the new created user profile document
     * @param subject the user UID to be stored in the OIDC subject property
     * @param context the main wiki context, to make sure the users are updated on the main wiki
     * @throws XWikiException
     */
    private void addOIDCObject(XWikiDocument userDoc, String subject, XWikiContext context) throws Exception
    {
        boolean addOIDCObj = getLDAPImportConfiguration().getIntValue("addOIDCObject") != 0;
        boolean oIDCClassExists = context.getWiki().exists(OIDC_CLASS, context);
        if (addOIDCObj && oIDCClassExists) {
            try {
                BaseObject oIDCObj = userDoc.getXObject(OIDC_CLASS, true, context);
                BaseObject clonedOIDCObject = oIDCObj.clone();
                oIDCObj.setStringValue("subject", subject);
                oIDCObj.setStringValue("issuer", getLDAPImportConfiguration().getStringValue("OIDCIssuer"));
                if (!oIDCObj.equals(clonedOIDCObject)) {
                    context.getWiki().saveDocument(userDoc, "OIDC user object added.", context);
                }
            } catch (XWikiException e) {
                logger.warn("Failed to attach OIDC object of [{}] type to the [{}] user profile.", OIDC_CLASS, userDoc,
                    e);
                throw e;
            }
        }
    }

    /**
     * Add the users in the XWiki group all the time, no matter what is in LDAP. WARNING: When the LDAP group mapping is
     * set and the mapping contains the current group, the user may be removed on group synchronization when the
     * membership is compared to the LDAP group one.
     *
     * @param groupName the XWiki group
     * @param users the list of users to be added in a group
     * @throws XWikiException in case of exception
     */
    private void addUsersInGroup(String groupName, Map<String, Map<String, String>> users) throws Exception
    {
        if (StringUtils.isNoneBlank(groupName)) {
            XWikiContext context = contextProvider.get();
            DocumentReference groupReference = documentReferenceResolver.resolve(groupName);
            XWikiDocument groupDocument = context.getWiki().getDocument(groupReference, context);
            boolean shouldSave = false;
            for (Entry<String, Map<String, String>> user : users.entrySet()) {
                String userFullName = user.getValue().get(USER_PROFILE_KEY);
                if (!context.getWiki().getUser(userFullName, context).isUserInGroup(groupName)) {
                    BaseObject memberObject = groupDocument.newXObject(GROUP_CLASS_REFERENCE, context);
                    memberObject.setStringValue(MEMBER, userFullName);
                    shouldSave = true;
                }
            }
            if (shouldSave) {
                context.getWiki().saveDocument(groupDocument, "Added users to group by LDAP User Import", context);
            }
        }
    }

    @Override
    public boolean hasImport() throws Exception
    {
        String value = getLDAPImportConfiguration().getStringValue("usersAllowedToImport");
        boolean hasImport = false;

        // Check if the current user is global admin.
        if (value.equals("globalAdmin") || StringUtils.isAllEmpty(value)) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN, GLOBAL_PREFERENCES);
        }

        // Check if the current user is local admin.
        if (!hasImport && value.equals("localAdmin")) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN);
        }

        // Check if the current user has edit right on the current group.
        if (!hasImport && value.equals("groupEditor")) {
            hasImport = contextualAuthorizationManager.hasAccess(Right.EDIT);
        }
        return hasImport;
    }

    private ConfigurationSource getConfigurationSource() throws Exception
    {
        if (componentManagerProvider.get().hasComponent(ConfigurationSource.class, ACTIVE_DIRECTORY_HINT)) {
            try {
                return componentManagerProvider.get().getInstance(ConfigurationSource.class, ACTIVE_DIRECTORY_HINT);
            } catch (ComponentLookupException e) {
                logger.error("Failed to get [{}] configuration source. Using the default LDAP configuration source",
                    ACTIVE_DIRECTORY_HINT, e);
                throw e;
            }
        }
        return configurationSource;
    }

    @Override
    public boolean displayedMax(int displayedUsersNb) throws Exception
    {
        return getMaxDisplayedUsersNb() == displayedUsersNb;
    }

    @Override
    public List<String> getXWikiMappedGroups() throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());
        List<String> groups = new ArrayList<>();
        for (String groupName : getConfiguration().getGroupMappings().keySet()) {
            groups.add(groupName);
        }
        context.setWikiId(currentWikiId);
        return groups;
    }

    @Override
    public int getGroupMemberSize(String xWikiGroupName) throws Exception
    {
        return getGroupMembers(xWikiGroupName).size();
    }

    private Map<String, String> getGroupMembers(String xWikiGroupName) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
            Set<String> ldapGroupDNs = configuration.getGroupMappings().get(xWikiGroupName);
            Map<String, String> members = new HashMap<>();
            for (String ldapGroupDN : ldapGroupDNs) {
                members.putAll(ldapUtils.getGroupMembers(ldapGroupDN, context));
            }
            return members;
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
            throw e;
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
    }

    @Override
    public boolean updateGroup(String xWikiGroupName) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        XWikiLDAPUtils ldapUtils = new XWikiLDAPUtils(connection, configuration);
        String uidAttributeName = configuration.getLDAPParam(LDAP_UID_ATTR, CN);
        ldapUtils.setUidAttributeName(uidAttributeName);
        ldapUtils.setBaseDN(configuration.getLDAPParam(LDAP_BASE_DN, ""));

        List<String> newUsersList = new ArrayList<>();
        Map<String, Map<String, String>> existingUsersMap = new HashMap<>();
        Map<String, String> groupMembersMap = new HashMap<>();

        Map<String, String> users = getGroupMembers(xWikiGroupName);
        // Fill the list of new users to be imported, the map of existing users to be synchronized and the users that
        // are members of the current group to update the group membership (can contain non-LDAP users).
        splitUsersList(context, uidAttributeName, ldapUtils, users, newUsersList, existingUsersMap, groupMembersMap);

        String[] newUsersArray = newUsersList.toArray(new String[newUsersList.size()]);
        // Call with null to not add users in group as the membership synch is done by synchronizeGroupMemberShip().
        importUsers(newUsersArray, null);

        synchronizeUsers(xWikiGroupName, context, currentWikiId, configuration, connection, ldapUtils,
            existingUsersMap);

        synchronizeGroupMembership(xWikiGroupName, groupMembersMap, configuration, connection, ldapUtils, context);

        context.setWikiId(currentWikiId);
        return false;
    }

    private void synchronizeUsers(String xWikiGroupName, XWikiContext context, String currentWikiId,
        XWikiLDAPConfig configuration, XWikiLDAPConnection connection, XWikiLDAPUtils ldapUtils,
        Map<String, Map<String, String>> usersToSynchronizeMap) throws Exception
    {
        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            configuration.setFinalProperty("ldap_update_user", "1");

            for (Entry<String, Map<String, String>> userToSynchronize : usersToSynchronizeMap.entrySet()) {
                String userId = userToSynchronize.getKey();
                DocumentReference userReference =
                    new DocumentReference(MAIN_WIKI_NAME, XWIKI, userToSynchronize.getValue().get(USERNAME));
                List<XWikiLDAPSearchAttribute> attributes =
                    ldapUtils.searchUserAttributesByUid(userId, getAttributeNameTable(configuration));
                XWikiDocument userDoc = context.getWiki().getDocument(userReference, context);
                ldapUtils.syncUser(userDoc, attributes, ldapUtils.searchUserDNByUid(userId), userId, context);
                // Make sure to get the latest version of the document, after LDAP synchronization.
                userDoc = context.getWiki().getDocument(userReference, context);
                addOIDCObject(userDoc, userId, context);
            }
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
            throw e;
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
    }

    private void synchronizeGroupMembership(String xWikiGroupName, Map<String, String> groupMembersMap,
        XWikiLDAPConfig configuration, XWikiLDAPConnection connection, XWikiLDAPUtils ldapUtils, XWikiContext context)
        throws Exception
    {
        Map<String, Set<String>> groupMappings = configuration.getGroupMappings();
        // Filter the group mapping to update only the membership of the users in the current group.
        Map<String, Set<String>> filteredGroupMapping = new HashMap<>();
        filteredGroupMapping.put(xWikiGroupName, groupMappings.get(xWikiGroupName));

        try {
            // Add all the XWiki users that are not LDAP users to be also synchronized(removed) in the current group.
            if (getLDAPImportConfiguration().getIntValue("forceXWikiUsersGroupMembershipUpdate") != 0) {
                DocumentReference xwikiGroupReference = documentReferenceResolver.resolve(xWikiGroupName);
                XWikiDocument groupDoc = context.getWiki().getDocument(xwikiGroupReference, context);
                List<BaseObject> xobjects =
                    groupDoc.getXObjects(documentReferenceResolver.resolve("XWiki.XWikiGroups"));
                for (BaseObject memberObj : xobjects) {
                    if (memberObj != null) {
                        String existingMember = memberObj.getStringValue(MEMBER);
                        if (StringUtils.isNoneBlank(existingMember) && !groupMembersMap.containsKey(existingMember)) {
                            groupMembersMap.put(existingMember, existingMember);
                        }
                    }
                }
            }

            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            for (Entry<String, String> user : groupMembersMap.entrySet()) {
                String xwikiUserName = user.getKey();
                String userDN = user.getValue();
                ldapUtils.syncGroupsMembership(xwikiUserName, userDN, filteredGroupMapping, context);
            }
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
            throw e;
        } finally {
            connection.close();
        }

    }

    private void splitUsersList(XWikiContext context, String uidAttributeName, XWikiLDAPUtils ldapUtils,
        Map<String, String> users, List<String> usersToImportList,
        Map<String, Map<String, String>> usersToSynchronizeMap, Map<String, String> groupMembersMap)
    {
        for (String userDN : users.keySet()) {
            String[] userDNFields = userDN.split(FIELDS_SEPARATOR);
            for (String userDNStringField : userDNFields) {
                String[] userDNField = userDNStringField.split(EQUAL_STRING);
                if (userDNField[0].equals(uidAttributeName)) {
                    // Check if user exists to know if should be imported on synchronized.
                    List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
                    String userId = userDNField[1];
                    searchAttributeList.add(new XWikiLDAPSearchAttribute(userDNField[0], userId));
                    String userPageName = ldapUtils.getUserPageName(searchAttributeList, context);
                    DocumentReference userReference = new DocumentReference(MAIN_WIKI_NAME, XWIKI, userPageName);
                    boolean userExists = context.getWiki().exists(userReference, context);
                    groupMembersMap.put(userReference.toString(), userDN);
                    if (!userExists) {
                        usersToImportList.add(userPageName);
                    } else {
                        Map<String, String> user = new HashMap<>();
                        user.put(USERNAME, userPageName);
                        user.put(USER_PROFILE_KEY, userReference.toString());
                        usersToSynchronizeMap.put(userId, user);
                    }
                    break;
                }
            }
        }
    }

    @Override
    public void updateGroups() throws Exception
    {
        boolean triggerGroupsUpdate = getLDAPImportConfiguration().getIntValue("triggerGroupsUpdate") != 0;
        if (triggerGroupsUpdate) {
            for (String xWikiGroupName : getXWikiMappedGroups()) {
                updateGroup(xWikiGroupName);
            }
        }
    }

    @Override
    public Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = getConfiguration();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);

        Map<String, Map<String, String>> ldapGroups = new HashMap<>();

        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            String filter =
                getGroupsFilter(searchInput, configuration.getLDAPParam(LDAP_GROUP_CLASSES_KEY, LDAP_GROUP_CLASSES));
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String[] attributeNameTable = new String[] {CN, "description"};

            PagedLDAPSearchResults result =
                connection.searchPaginated(base, LDAPConnection.SCOPE_SUB, filter, attributeNameTable, false);
            if (result.hasMore()) {
                ldapGroups = getLDAPGroups(configuration, connection, result, context, xWikiGroupName);
            } else {
                logger.warn("There are no result for base dn: [{}], search scope: [{}], filter: [{}], fields: [{}].",
                    base, LDAPConnection.SCOPE_SUB, filter, CN);
                return null;
            }
        } catch (XWikiLDAPException e) {
            logger.error(e.getFullMessage());
            throw e;
        } catch (Exception e) {
            logger.warn("Failed to search for value [{}] in the fields [{}].", e);
            throw e;
        } finally {
            connection.close();
            context.setWikiId(currentWikiId);
        }
        return ldapGroups;
    }

    private Map<String, Map<String, String>> getLDAPGroups(XWikiLDAPConfig configuration,
        XWikiLDAPConnection connection, PagedLDAPSearchResults result, XWikiContext context, String xWikiGroupName)
        throws Exception
    {
        LDAPEntry resultEntry = null;

        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                int maxDisplayedUsersNb = getMaxDisplayedUsersNb();
                boolean hasMore;
                Map<String, Map<String, String>> groupsMap = new HashMap<>();
                Map<String, Set<String>> ldapGroupMapping = configuration.getGroupMappings();
                do {
                    Map<String, String> group =
                        getLDAPGroupDetails(connection, xWikiGroupName, resultEntry, ldapGroupMapping);
                    groupsMap.put(group.get(CN), group);
                    hasMore = result.hasMore();
                    resultEntry = hasMore ? result.next() : null;
                } while (resultEntry != null && groupsMap.size() < maxDisplayedUsersNb);
                // Only do the sorting on the UI side when we have less results than the limit or exactly the limit.
                // hasMore is false when groupsMap.size() <= maxDisplayedUsersNb.
                if (!hasMore) {
                    SortedMap<String, Map<String, String>> sortedGroupsMap = new TreeMap<>();
                    for (String groupId : groupsMap.keySet()) {
                        sortedGroupsMap.put(groupId, groupsMap.get(groupId));
                    }
                    return sortedGroupsMap;
                }
                return groupsMap;
            }
        } catch (Exception e) {
            logger.warn(FAILED_TO_GET_RESULTS, e);
            if (e instanceof LDAPReferralException) {
                logger.warn(((LDAPReferralException) e).getFailedReferral());
            }
            throw e;
        }
        return Collections.emptyMap();
    }

    private Map<String, String> getLDAPGroupDetails(XWikiLDAPConnection connection, String xWikiGroupName,
        LDAPEntry resultEntry, Map<String, Set<String>> groupMappings)
    {
        List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
        connection.ldapToXWikiAttribute(searchAttributeList, resultEntry.getAttributeSet());

        Map<String, String> group = new HashMap<>();
        for (XWikiLDAPSearchAttribute attribute : searchAttributeList) {
            group.put(attribute.name, attribute.value);
        }
        String ldapGroupDN = resultEntry.getDN();
        group.put("dn", ldapGroupDN);
        boolean isAssociated = false;
        if (groupMappings.get(xWikiGroupName) != null && groupMappings.get(xWikiGroupName).contains(ldapGroupDN)) {
            isAssociated = true;
        }
        group.put("isAssociated", Boolean.toString(isAssociated));
        return group;
    }

    @Override
    public boolean associateGroups(String[] ldapGroupsArray, String xWikiGroupName) throws Exception
    {
        if (ldapGroupsArray.length > 0) {
            XWikiContext context = contextProvider.get();
            String currentWikiId = context.getWikiId();
            // Make sure to use the main wiki configuration source.
            context.setWikiId(context.getMainXWiki());

            DocumentReference configSourceDocRef = GLOBAL_PREFERENCES;

            if (componentManagerProvider.get().hasComponent(ConfigurationSource.class, ACTIVE_DIRECTORY_HINT)) {
                configSourceDocRef = new DocumentReference(MAIN_WIKI_NAME, Arrays.asList("ActiveDirectory", "Code"),
                    "ActiveDirectoryConfig");
            }

            try {

                XWikiDocument configSourceDoc = context.getWiki().getDocument(configSourceDocRef, context);

                Set<String> ldapGroupsSetToAdd = new HashSet<String>(Arrays.asList(ldapGroupsArray));
                Map<String, Set<String>> groupMapping = getConfiguration().getGroupMappings();
                for (String key : groupMapping.keySet()) {
                    Set<String> modifiedSet =
                        groupMapping.get(key).stream().map((value) -> StringUtils.replace(value, "\\", "\\\\"))
                            .collect(Collectors.toSet());
                    groupMapping.put(key, modifiedSet);
                }
                Set<String> ldapGroupsSet = new HashSet<>();
                if (groupMapping.get(xWikiGroupName) != null) {
                    ldapGroupsSet.addAll(groupMapping.get(xWikiGroupName));
                }
                ldapGroupsSet.addAll(ldapGroupsSetToAdd);

                groupMapping.put(xWikiGroupName, ldapGroupsSet);

                StringBuffer groupMappingStringBuffer = new StringBuffer();

                for (Entry<String, Set<String>> entry : groupMapping.entrySet()) {
                    for (String ldapGroupDN : entry.getValue()) {
                        groupMappingStringBuffer.append(entry.getKey()).append(EQUAL_STRING).append(ldapGroupDN)
                            .append("|");
                    }
                }

                // Remove the last pipe separator from the mapping.
                String groupMappingString = StringUtils.chop(groupMappingStringBuffer.toString());

                BaseObject preferencesObject = configSourceDoc.getXObject(PREFERENCES_REFERENCE);

                preferencesObject.setLargeStringValue("ldap_group_mapping", groupMappingString);

                context.getWiki().saveDocument(configSourceDoc,
                    "Updated the LDAP group mapping by LDAP User Import app", context);
                return true;
            } catch (XWikiException e) {
                logger.error("Failed to associate LDAP group to XWiki group", e);
                throw e;
            } finally {
                context.setWikiId(currentWikiId);
            }
        }
        return false;
    }
}
