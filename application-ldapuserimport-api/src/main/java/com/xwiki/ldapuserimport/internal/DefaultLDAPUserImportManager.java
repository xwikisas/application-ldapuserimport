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
import org.xwiki.component.manager.ComponentManager;
import org.xwiki.configuration.ConfigurationSource;
import org.xwiki.contrib.ldap.LDAPProfileXClass;
import org.xwiki.contrib.ldap.PagedLDAPSearchResults;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;
import org.xwiki.model.ModelContext;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.LocalDocumentReference;
import org.xwiki.rendering.syntax.Syntax;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.security.authorization.Right;

import com.novell.ldap.LDAPConnection;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPReferralException;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xwiki.ldapuserimport.LDAPUserImportConfiguration;
import com.xwiki.ldapuserimport.LDAPUserImportManager;

import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.CN;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.LDAP_BASE_DN;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.UID;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getGroupsFilter;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getUserAttributes;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getUserFieldsMap;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getUsersFilter;
import static com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper.getXWikiLDAPUtils;

/**
 * @version $Id$
 * @since 2.6
 */
@Component
@Singleton
public class DefaultLDAPUserImportManager implements LDAPUserImportManager
{
    private static final String OU = "ou";

    private static final String MEMBER = "member";

    private static final String XWIKI_PREFERENCES = "XWikiPreferences";

    private static final String ACTIVE_DIRECTORY_HINT = "activedirectory";

    private static final String USERNAME = "username";

    private static final Map<String, String> DEFAULT_LDAP_FIELDS_MAPPING = new HashMap<String, String>()
    {
        {
            put("first_name", "givenName");
            put("last_name", "sn");
            put("email", "mail");
        }
    };

    private static final String USER_PROFILE_KEY = "userProfile";

    private static final String USER_PROFILE_URL_KEY = "userProfileURL";

    private static final String EQUAL_STRING = "=";

    private static final LocalDocumentReference PREFERENCES_REFERENCE =
        new LocalDocumentReference(XWiki.SYSTEM_SPACE, XWIKI_PREFERENCES);

    private static final DocumentReference GLOBAL_PREFERENCES =
        new DocumentReference(XWiki.DEFAULT_MAIN_WIKI, XWiki.SYSTEM_SPACE, XWIKI_PREFERENCES);

    private static final String DN = "dn";

    private static final String FAILED_TO_GET_RESULTS = "Failed to get results";

    private static final DocumentReference OIDC_CLASS =
        new DocumentReference(XWiki.DEFAULT_MAIN_WIKI, Arrays.asList(XWiki.SYSTEM_SPACE, "OIDC"), "UserClass");

    private static final LocalDocumentReference GROUP_CLASS_REFERENCE =
        new LocalDocumentReference(XWiki.SYSTEM_SPACE, "XWikiGroups");

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

    @Inject
    private Provider<XWikiLDAPConfig> xwikiLDAPConfigProvider;

    @Inject
    private LDAPUserImportConfiguration ldapUserImportConfiguration;

    @Inject
    @Named("compact")
    private EntityReferenceSerializer<String> serializer;

    @Inject
    private ModelContext modelContext;

    /**
     * Get all the users that have the searched value contained in any of the provided fields value.
     */
    @Override
    public Map<String, Map<String, String>> getUsers(String singleField, String allFields,
        String searchInput, boolean isFullSearch) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = xwikiLDAPConfigProvider.get();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        String loginDN = configuration.getLDAPBindDN();
        String password = configuration.getLDAPBindPassword();

        try {
            connection.open(loginDN, password, context);
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String[] attributeNameTable = getUserAttributes(configuration, DEFAULT_LDAP_FIELDS_MAPPING);

            String filter;
            if (StringUtils.isNoneBlank(singleField)) {
                filter = getUsersFilter(searchInput, singleField, configuration, isFullSearch);
            } else if (StringUtils.isNoneBlank(allFields)) {
                filter = getUsersFilter(searchInput, allFields, configuration, isFullSearch);
            } else {
                filter = getUsersFilter(searchInput, attributeNameTable, configuration, isFullSearch);
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

    private Map<String, Map<String, String>> getUsers(XWikiLDAPConfig configuration, XWikiLDAPConnection connection,
        PagedLDAPSearchResults result, XWikiContext context) throws Exception
    {
        XWikiLDAPUtils ldapUtils = getXWikiLDAPUtils(configuration, connection);
        LDAPEntry resultEntry = null;

        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                Map<String, String> fieldsMap = getUserFieldsMap(configuration, DEFAULT_LDAP_FIELDS_MAPPING);
                int maxDisplayedUsersNb = ldapUserImportConfiguration.getMaxUserImportWizardResults();
                boolean hasMore;
                Map<String, Map<String, String>> usersMap = new HashMap<>();
                do {
                    Map<String, String> user = getUserDetails(connection, fieldsMap, ldapUtils, context, resultEntry);
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

    private Map<String, String> getUserDetails(XWikiLDAPConnection connection, Map<String, String> fieldsMap,
        XWikiLDAPUtils ldapUtils, XWikiContext context, LDAPEntry resultEntry)
    {
        String uidFieldValue = getAttributeValue(ldapUtils.getUidAttributeName(), resultEntry);
        if (StringUtils.isNoneBlank(uidFieldValue)) {
            List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
            connection.ldapToXWikiAttribute(searchAttributeList, resultEntry.getAttributeSet());
            String userPageName = ldapUtils.getUserPageName(searchAttributeList, context);
            DocumentReference userReference =
                new DocumentReference(XWiki.DEFAULT_MAIN_WIKI, XWiki.SYSTEM_SPACE, userPageName);
            return getUserDetails(fieldsMap, searchAttributeList, userReference, context);
        }
        return Collections.emptyMap();
    }

    private Map<String, String> getUserDetails(Map<String, String> fieldsMap, List<XWikiLDAPSearchAttribute> attributes,
        DocumentReference userReference, XWikiContext context)
    {
        Map<String, String> user = new HashMap<>();
        boolean userExists = false;
        try {
            userExists = context.getWiki().exists(userReference, context);
        } catch (XWikiException e) {
            logger.warn("An exception was thrown while checking if [{}] exists.", userReference);
            return Collections.emptyMap();
        }
        if (userExists) {
            user.put(USER_PROFILE_URL_KEY, context.getWiki().getURL(userReference, context));
        }
        user.put(USER_PROFILE_KEY, serializer.serialize(userReference, modelContext.getCurrentEntityReference()));
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

            XWikiLDAPConfig configuration = xwikiLDAPConfigProvider.get();
            XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
            XWikiLDAPUtils ldapUtils = getXWikiLDAPUtils(configuration, connection);

            try {
                connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);

                SortedMap<String, Map<String, String>> users = new TreeMap<>();

                String[] attributeNameTable = getUserAttributes(configuration, DEFAULT_LDAP_FIELDS_MAPPING);
                Map<String, String> fieldsMap = getUserFieldsMap(configuration, DEFAULT_LDAP_FIELDS_MAPPING);
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
        boolean addOIDCObj = ldapUserImportConfiguration.getAddOIDCObject();
        boolean oIDCClassExists = context.getWiki().exists(OIDC_CLASS, context);
        if (addOIDCObj && oIDCClassExists) {
            try {
                BaseObject oIDCObj = userDoc.getXObject(OIDC_CLASS, true, context);
                BaseObject clonedOIDCObject = oIDCObj.clone();
                oIDCObj.setStringValue("subject", subject);
                oIDCObj.setStringValue("issuer", ldapUserImportConfiguration.getOIDCIssuer());
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
        boolean hasImport = false;

        switch (ldapUserImportConfiguration.getUserImportPolicy()) {
            case GLOBAL_AND_LOCAL_ADMINS:
                hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN);
                break;
            case GROUP_EDITORS:
                hasImport = contextualAuthorizationManager.hasAccess(Right.EDIT);
                break;
            default:
                hasImport = contextualAuthorizationManager.hasAccess(Right.ADMIN, GLOBAL_PREFERENCES);
                break;
        }

        return hasImport;
    }

    @Override
    public boolean displayedMax(int displayedUsersNb) throws Exception
    {
        return ldapUserImportConfiguration.getMaxUserImportWizardResults() == displayedUsersNb;
    }

    @Override
    public List<String> getXWikiMappedGroups() throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());
        List<String> groups = new ArrayList<>();
        for (String groupName : xwikiLDAPConfigProvider.get().getGroupMappings().keySet()) {
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

    /**
     * Get members of an LDAP group, knowing the associated XWiki Group.
     *
     * @param xWikiGroupName XWiki Group name
     * @return the group members, as a pair of dn and uidAttribute in lowercase
     * @throws Exception in case of error while accessing the members of the group
     */
    private Map<String, String> getGroupMembers(String xWikiGroupName) throws Exception
    {
        return getGroupMembers(xWikiGroupName, false);
    }

    /**
     * Get members of an LDAP group, knowing the associated XWiki Group.
     *
     * @param xWikiGroupName XWiki Group name
     * @param caseSensitive {@code true} if the resulted values should respect the defined case-sensitive values, or
     *     {@code false} if lowercase values will be used
     * @return the group members, as a pair of dn and uidAttribute
     * @throws Exception in case of error while accessing the members or their case-sensitive values
     */
    private Map<String, String> getGroupMembers(String xWikiGroupName, boolean caseSensitive) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = xwikiLDAPConfigProvider.get();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            XWikiLDAPUtils ldapUtils = getXWikiLDAPUtils(configuration, connection);

            Set<String> ldapGroupDNs = configuration.getGroupMappings().get(xWikiGroupName);
            String groupMembershipAttribute = ldapUserImportConfiguration.getGroupMembershipAttribute();
            if (StringUtils.isNotBlank(groupMembershipAttribute)) {
                String filterPrefix = groupMembershipAttribute + '=';
                Set<String> filters = ldapGroupDNs
                    .stream()
                    .filter(ldapGroupDn -> !ldapGroupDn.startsWith(filterPrefix))
                    .map(ldapGroupDn -> filterPrefix + ldapGroupDn)
                    .collect(Collectors.toSet());
                ldapGroupDNs.addAll(filters);
            }
            Map<String, String> members = new HashMap<>();
            for (String ldapGroupDN : ldapGroupDNs) {
                Map<String, String> groupMembers = ldapUtils.getGroupMembers(ldapGroupDN, context);
                if (groupMembers == null) {
                    continue;
                }
                if (caseSensitive) {
                    members.putAll(getGroupMembersCaseSensitive(groupMembers, ldapUtils));
                } else {
                    members.putAll(groupMembers);
                }
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

    /**
     * Collect the case-sensitive values of the group members.
     *
     * @param groupMembers group members as a pair of dn and uidAttribute in lowercase
     * @param ldapUtils LDAP communication tool
     * @return the group members as a pair of case-sensitive dn and uidAttribute
     */
    private Map<String, String> getGroupMembersCaseSensitive(Map<String, String> groupMembers, XWikiLDAPUtils ldapUtils)
    {
        logger.info("Collect case-sensitive information for this group.");
        Map<String, String> membersCaseSensitive = new HashMap<>();
        for (Entry<String, String> member : groupMembers.entrySet()) {
            // Search for the exact values.
            List<XWikiLDAPSearchAttribute> attributes = ldapUtils.searchUserAttributesByUid(member.getValue(),
                new String[] { ldapUtils.getUidAttributeName() });

            if (attributes != null) {
                // Collect the case-sensitive values from the search response.
                XWikiLDAPSearchAttribute uidAttribute =
                    attributes.stream().filter(entry -> entry.name.equals(ldapUtils.getUidAttributeName())).findFirst()
                        .orElse(null);
                XWikiLDAPSearchAttribute dn =
                    attributes.stream().filter(entry -> entry.name.equals(DN)).findFirst().orElse(null);
                if (uidAttribute != null && dn != null) {
                    membersCaseSensitive.put(dn.value, uidAttribute.value);
                }
            }
        }

        return membersCaseSensitive;
    }

    @Override
    public boolean updateGroup(String xWikiGroupName) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = xwikiLDAPConfigProvider.get();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);
        XWikiLDAPUtils ldapUtils = getXWikiLDAPUtils(configuration, connection);

        List<String> newUsersList = new ArrayList<>();
        Map<String, Map<String, String>> existingUsersMap = new HashMap<>();
        Map<String, String> groupMembersMap = new HashMap<>();

        // Get group members in case-sensitive since the uidAttribute value will be used for the page name.
        // Retrieve all the ldap users that are part of the ldap groups mapped by the xwiki group.
        Map<String, String> users = getGroupMembers(xWikiGroupName, true);

        // Fill in the list of new users to be imported, the map of existing users to be synchronized and the users that
        // are members of the current group to update the group membership (can contain non-LDAP users).
        splitUsersList(context, ldapUtils, users, newUsersList, existingUsersMap, groupMembersMap);

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
                DocumentReference userReference = new DocumentReference(XWiki.DEFAULT_MAIN_WIKI, XWiki.SYSTEM_SPACE,
                    userToSynchronize.getValue().get(USERNAME));
                List<XWikiLDAPSearchAttribute> attributes =
                    ldapUtils.searchUserAttributesByUid(userId,
                        getUserAttributes(configuration, DEFAULT_LDAP_FIELDS_MAPPING));
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

    protected XWikiDocument getGroupDocument(String groupName, XWikiContext context) throws XWikiException
    {
        BaseClass groupClass = context.getWiki().getGroupClass(context);

        // Get document representing group
        XWikiDocument groupDoc = context.getWiki().getDocument(groupName, context);
        return groupDoc;
    }

    protected void saveGroupDocument(XWikiDocument groupDoc, String groupName, XWikiContext context)
    {
        try {
            // If the document is new, set its content
            if (groupDoc.isNew()) {
                groupDoc.setSyntax(Syntax.XWIKI_2_0);
                groupDoc.setContent("{{include reference='XWiki.XWikiGroupSheet' /}}");
            }

            // Save modifications
            context.getWiki().saveDocument(groupDoc, context);
            logger.debug("Saving xwiki group [{}]", groupName);
        } catch (Exception e) {
            logger.error("Failed saving group [{}]", groupName, e);
        }
    }

    protected void addUserToXWikiGroup(String xwikiUserName, XWikiDocument groupDoc,
        String groupName, XWikiContext context)
    {
        try {
            logger.debug("Adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);
            BaseClass groupClass = context.getWiki().getGroupClass(context);
            synchronized (groupDoc) {

                // Add a member object to document
                BaseObject memberObj = groupDoc.newXObject(groupClass.getDocumentReference(), context);
                Map<String, String> map = new HashMap<>();
                map.put(MEMBER, xwikiUserName);
                groupClass.fromMap(map, memberObj);
            }
            logger.debug("Finished adding user [{}] to xwiki group [{}]", xwikiUserName, groupName);
        } catch (Exception e) {
            logger.error("Failed to add a user [{}] to a group [{}]", xwikiUserName, groupName, e);
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

            int nbUsers = 0;
            int maxNbUsers = 500;
            XWikiDocument groupDoc = getGroupDocument(xWikiGroupName, context);
            Set<String> usersNotInLDAPGroups = new HashSet<>();
            synchronized (groupDoc) {
                BaseClass groupClass = context.getWiki().getGroupClass(context);
                // Clean the users that are already in the group.
                updateGroupMembersMap(groupMembersMap, groupDoc, groupClass, usersNotInLDAPGroups);
                nbUsers = addUsersToGroup(xWikiGroupName, groupMembersMap, context, groupDoc, nbUsers, maxNbUsers);
                nbUsers =
                    removeUsersFromGroup(xWikiGroupName, context, usersNotInLDAPGroups, groupDoc, groupClass, nbUsers,
                        maxNbUsers);

                if (nbUsers > 0) {
                    saveGroupDocument(groupDoc, xWikiGroupName, context);
                }
            }
        } catch (XWikiException e) {
            logger.error(e.getFullMessage());
            throw e;
        }
    }

    private int addUsersToGroup(String xWikiGroupName, Map<String, String> groupMembersMap, XWikiContext context,
        XWikiDocument groupDoc, int nbUsers, int maxNbUsers)
    {
        // Add the ldap users that are not already part of the group.
        int groupChanges = nbUsers;
        for (Entry<String, String> user : groupMembersMap.entrySet()) {
            String xwikiUserName = user.getKey();
            String userDN = user.getValue();
            addUserToXWikiGroup(xwikiUserName, groupDoc, xWikiGroupName, context);
            groupChanges++;
            // The goal is to save the group Document after adding enough users
            if (groupChanges >= maxNbUsers) {
                groupChanges = 0;
                saveGroupDocument(groupDoc, xWikiGroupName, context);
            }
        }
        return groupChanges;
    }

    private int removeUsersFromGroup(String xWikiGroupName, XWikiContext context, Set<String> usersNotInLDAPGroups,
        XWikiDocument groupDoc, BaseClass groupClass, int nbUsers, int maxNbUsers) throws XWikiException
    {
        // Remove the users that are part of the xwiki group but not of the ldap group. They were probably
        // removed from the ldap group.
        int groupUpdates = nbUsers;
        LDAPProfileXClass ldapXClass = new LDAPProfileXClass(context);
        for (String userNotInLDAPGroups : usersNotInLDAPGroups) {
            XWikiDocument userProfile = context.getWiki()
                .getDocument(documentReferenceResolver.resolve(userNotInLDAPGroups), context);
            // Do not remove non-ldap users.
            if (ldapXClass.getDn(userProfile) == null && ldapXClass.getUid(userProfile) == null) {
                continue;
            }
            // Get and remove the specific group membership object for the user
            BaseObject groupObj =
                groupDoc.getXObject(groupClass.getDocumentReference(), MEMBER, userNotInLDAPGroups);
            if (groupObj != null) {
                groupDoc.removeXObject(groupObj);
                groupUpdates++;
            }
            if (groupUpdates >= maxNbUsers) {
                groupUpdates = 0;
                saveGroupDocument(groupDoc, xWikiGroupName, context);
            }
        }
        return groupUpdates;
    }

    private void updateGroupMembersMap(Map<String, String> groupMembersMap, XWikiDocument groupDoc,
        BaseClass groupClass,
        Set<String> usersNotInLDAPGroups)
    {
        List<BaseObject> xobjects = groupDoc.getXObjects(groupClass.getDocumentReference());
        if (xobjects != null) {
            for (BaseObject memberObj : xobjects) {
                if (memberObj == null) {
                    continue;
                }
                String existingMember = memberObj.getStringValue(MEMBER);
                if (existingMember == null || existingMember.isEmpty()) {
                    continue;
                }
                if (groupMembersMap.remove(existingMember) != null) {
                    logger.warn("User [{}] already exist in group [{}]", existingMember,
                        groupDoc.getDocumentReference());
                } else {
                    usersNotInLDAPGroups.add(existingMember);
                }
            }
        }
    }

    private void splitUsersList(XWikiContext context, XWikiLDAPUtils ldapUtils, Map<String, String> users,
        List<String> usersToImportList, Map<String, Map<String, String>> usersToSynchronizeMap,
        Map<String, String> groupMembersMap)
    {
        for (Entry<String, String> entry : users.entrySet()) {
            String uidAttribute = entry.getValue();
            // Check if user exists to know if should be imported on synchronized, using the existing profile.
            List<XWikiLDAPSearchAttribute> searchAttributeList = new ArrayList<>();
            searchAttributeList.add(new XWikiLDAPSearchAttribute(ldapUtils.getUidAttributeName(), uidAttribute));
            String userPageName = ldapUtils.getUserPageName(searchAttributeList, context);

            DocumentReference userReference =
                new DocumentReference(XWiki.DEFAULT_MAIN_WIKI, XWiki.SYSTEM_SPACE, userPageName);
            boolean userExists = false;
            try {
                userExists = context.getWiki().exists(userReference, context);
            } catch (XWikiException e) {
                logger.warn("Failed to check whether [{}] exists or not.", userReference);
                continue;
            }
            groupMembersMap.put(serializer.serialize(userReference, modelContext.getCurrentEntityReference()),
                entry.getKey());
            if (!userExists) {
                usersToImportList.add(uidAttribute);
            } else {
                Map<String, String> user = new HashMap<>();
                user.put(USERNAME, userPageName);
                user.put(USER_PROFILE_KEY,
                    serializer.serialize(userReference, modelContext.getCurrentEntityReference()));
                usersToSynchronizeMap.put(uidAttribute, user);
            }
        }
    }

    @Override
    public void updateGroups() throws Exception
    {
        if (ldapUserImportConfiguration.getTriggerGroupUpdate()) {
            for (String xWikiGroupName : getXWikiMappedGroups()) {
                updateGroup(xWikiGroupName);
            }
        }
    }

    @Override
    public Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName,
        boolean isFullSearch) throws Exception
    {
        return getLDAPGroups(searchInput, xWikiGroupName, isFullSearch, false);
    }

    @Override
    public Map<String, Map<String, String>> getLDAPGroups(String searchInput, String xWikiGroupName,
        boolean isFullSearch, boolean isOUSearch) throws Exception
    {
        XWikiContext context = contextProvider.get();
        String currentWikiId = context.getWikiId();
        // Make sure to use the main wiki configuration source.
        context.setWikiId(context.getMainXWiki());

        XWikiLDAPConfig configuration = xwikiLDAPConfigProvider.get();
        XWikiLDAPConnection connection = new XWikiLDAPConnection(configuration);

        Map<String, Map<String, String>> ldapGroups = new HashMap<>();

        try {
            connection.open(configuration.getLDAPBindDN(), configuration.getLDAPBindPassword(), context);
            String filter = isOUSearch
                ? XWikiLDAPUtilsHelper.getSearchFilter("organizationalUnit", searchInput, new String[] { OU },
                isFullSearch) : getGroupsFilter(searchInput, configuration, isFullSearch);
            String base = configuration.getLDAPParam(LDAP_BASE_DN, "");

            String[] attributeNameTable = new String[] { isOUSearch ? OU : CN, "description" };

            PagedLDAPSearchResults result =
                connection.searchPaginated(base, LDAPConnection.SCOPE_SUB, filter, attributeNameTable, false);
            if (result.hasMore()) {
                ldapGroups =
                    getLDAPGroups(configuration, connection, result, context, xWikiGroupName, isFullSearch, isOUSearch);
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
        XWikiLDAPConnection connection, PagedLDAPSearchResults result, XWikiContext context, String xWikiGroupName,
        boolean isFullSearch, boolean isOUSearch) throws Exception
    {
        LDAPEntry resultEntry = null;

        try {
            resultEntry = result.next();
            if (resultEntry != null) {
                int maxDisplayedUsersNb = ldapUserImportConfiguration.getMaxUserImportWizardResults();
                boolean hasMore;
                Map<String, Map<String, String>> groupsMap = new HashMap<>();
                Map<String, Set<String>> ldapGroupMapping = configuration.getGroupMappings();
                do {
                    Map<String, String> group =
                        getLDAPGroupDetails(connection, xWikiGroupName, resultEntry, ldapGroupMapping);
                    if (isOUSearch) {
                        groupsMap.put(group.get(OU), group);
                    } else {
                        groupsMap.put(group.get(CN), group);
                    }
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
        group.put(DN, ldapGroupDN);
        boolean isAssociated = false;
        if (StringUtils.isNotBlank(xWikiGroupName)) {
            if (groupMappings.get(xWikiGroupName) != null && groupMappings.get(xWikiGroupName).contains(ldapGroupDN)) {
                isAssociated = true;
            }
        } else {
            // In the case where no xWikiGroupName is provided, look through the existing mappings to check if one of
            // them contains the current DN
            for (Map.Entry<String, Set<String>> mapping : groupMappings.entrySet()) {
                if (mapping.getValue().contains(ldapGroupDN)) {
                    isAssociated = true;
                    // Due to limitations to the return format of #getLDAPGroupDetails,
                    // we currently cannot return more than one group mapping.
                    group.put("xwikiGroup", mapping.getKey());
                }
            }
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
                configSourceDocRef = new DocumentReference(XWiki.DEFAULT_MAIN_WIKI,
                    Arrays.asList("ActiveDirectory", "Code"), "ActiveDirectoryConfig");
            }

            try {

                XWikiDocument configSourceDoc = context.getWiki().getDocument(configSourceDocRef, context);

                Set<String> ldapGroupsSetToAdd = new HashSet<String>(Arrays.asList(ldapGroupsArray));
                Map<String, Set<String>> groupMapping = xwikiLDAPConfigProvider.get().getGroupMappings();
                for (Entry<String, Set<String>> entry : groupMapping.entrySet()) {
                    Set<String> modifiedSet =
                        entry.getValue().stream().map((value) -> StringUtils.replace(value, "\\", "\\\\"))
                            .collect(Collectors.toSet());
                    entry.setValue(modifiedSet);
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
