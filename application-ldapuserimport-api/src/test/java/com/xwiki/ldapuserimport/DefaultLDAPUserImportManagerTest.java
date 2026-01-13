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

import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.stream.Collectors;

import javax.inject.Named;
import javax.inject.Provider;

import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.mockito.Mock;
import org.slf4j.Logger;
import org.xwiki.component.util.ReflectionUtils;
import org.xwiki.contrib.ldap.LDAPProfileXClass;
import org.xwiki.contrib.ldap.PagedLDAPSearchResults;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPConnection;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.contrib.ldap.XWikiLDAPUtils;
import org.xwiki.model.ModelContext;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.DocumentReferenceResolver;
import org.xwiki.model.reference.EntityReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.model.reference.WikiReference;
import org.xwiki.security.authorization.ContextualAuthorizationManager;
import org.xwiki.test.TestComponentManager;
import org.xwiki.test.junit5.mockito.ComponentTest;
import org.xwiki.test.junit5.mockito.InjectMockComponents;
import org.xwiki.test.junit5.mockito.MockComponent;

import com.novell.ldap.LDAPAttributeSet;
import com.novell.ldap.LDAPEntry;
import com.novell.ldap.LDAPException;
import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.api.User;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xpn.xwiki.objects.BaseObject;
import com.xpn.xwiki.objects.classes.BaseClass;
import com.xpn.xwiki.web.Utils;
import com.xwiki.ldapuserimport.internal.DefaultLDAPUserImportManager;
import com.xwiki.ldapuserimport.internal.XWikiLDAPFactory;

import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyBoolean;
import static org.mockito.ArgumentMatchers.anyInt;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

@ComponentTest
public class DefaultLDAPUserImportManagerTest
{
    private static final String WIKI_ID = "xwiki";

    private static final String MAIN_SPACE = "XWiki";

    private static final String XWIKI_GROUP = "XWiki.Group1";

    private static final String LDAP_UID_ATTR = "uid";

    private static final DocumentReference REF_USER = new DocumentReference(WIKI_ID, MAIN_SPACE, "User1");

    private static final DocumentReference REF_GROUP = new DocumentReference(WIKI_ID, MAIN_SPACE, "Group1");

    @InjectMockComponents
    private DefaultLDAPUserImportManager defaultLDAPUserImportManager;

    @MockComponent
    private ContextualAuthorizationManager contextualAuthorizationManager;

    @MockComponent
    private DocumentReferenceResolver<String> documentReferenceResolver;

    @MockComponent
    private Logger logger;

    @MockComponent
    private Provider<XWikiContext> contextProvider;

    @MockComponent
    private Provider<XWikiLDAPConfig> xwikiLDAPConfigProvider;

    @MockComponent
    private LDAPUserImportConfiguration ldapUserImportConfiguration;

    @MockComponent
    @Named("compact")
    private EntityReferenceSerializer<String> serializer;

    @MockComponent
    private ModelContext modelContext;

    @MockComponent
    private XWikiLDAPFactory xWikiLDAPFactory;

    @Mock
    private XWikiContext context;

    @Mock
    private XWiki xWiki;

    @Mock
    private XWikiLDAPConfig ldapConfig;

    @Mock
    private XWikiLDAPConnection xWikiLDAPConnection;

    @Mock
    private XWikiLDAPUtils xWikiLDAPUtils;

    @Mock
    private PagedLDAPSearchResults searchResults;

    @Mock
    private XWikiDocument groupDocument;

    @Mock
    private BaseObject groupObject;

    @Mock
    private BaseClass groupClass;

    @Mock
    private LDAPProfileXClass ldapProfileXClass;

    private TestComponentManager testComponentManager;

    @BeforeEach
    public void setup(TestComponentManager componentManager) throws Exception
    {
        ReflectionUtils.setFieldValue(this.defaultLDAPUserImportManager, "logger", this.logger);

        testComponentManager = componentManager;
        Utils.setComponentManager(testComponentManager);
        testComponentManager.registerComponent(DocumentReferenceResolver.TYPE_STRING, "currentmixed", mock(
            DocumentReferenceResolver.class));

        when(this.ldapUserImportConfiguration.getMaxUserImportWizardResults()).thenReturn(10);
        when(this.ldapUserImportConfiguration.getAddOIDCObject()).thenReturn(true);
        when(this.ldapUserImportConfiguration.getOIDCIssuer()).thenReturn("test");
        when(this.ldapUserImportConfiguration.getGroupMembershipAttribute()).thenReturn("");
        when(this.ldapUserImportConfiguration.getForceUserGroupMembershipUpdate()).thenReturn(true);
        when(this.ldapUserImportConfiguration.getTriggerGroupUpdate()).thenReturn(true);
        when(this.ldapUserImportConfiguration.getTriggerGroupUpdate()).thenReturn(true);
        when(this.ldapUserImportConfiguration.getUserImportPolicy()).thenReturn(
            LDAPUserImportConfiguration.UserImportPolicy.GROUP_EDITORS);

        when(this.ldapConfig.getLDAPPort()).thenReturn(1234);
        when(this.ldapConfig.getLDAPBindDN()).thenReturn("binddn");
        when(this.ldapConfig.getLDAPBindPassword()).thenReturn("pass");
        when(this.ldapConfig.getGroupMappings()).thenReturn(Map.of(XWIKI_GROUP, Set.of("ldapgroup")));
        when(this.ldapConfig.getLDAPParam(any(), any()))
            .thenAnswer(inv -> inv.getArgument(1));
        when(this.ldapConfig.getUserMappings(any())).thenReturn(Collections.emptyMap());

        when(this.xWikiLDAPUtils.getUidAttributeName()).thenReturn(LDAP_UID_ATTR);

        when(this.contextualAuthorizationManager.hasAccess(any())).thenReturn(true);

        when(this.documentReferenceResolver.resolve(any())).thenAnswer((invocation -> {
            String argument = invocation.getArgument(0);
            List<String> wikiSplit = Arrays.asList(argument.split(":"));
            String wiki = WIKI_ID;
            String ref = argument;
            if (wikiSplit.size() > 1) {
                wiki = wikiSplit.get(0);
                ref = wikiSplit.get(1);
            }
            List<String> split = Arrays.asList(ref.split("\\."));
            if (split.size() == 1) {
                return new DocumentReference(wiki, split.get(0), "WebHome");
            }
            return new DocumentReference(wiki, split.subList(0, split.size() - 1), split.get(split.size() - 1));
        }));

        when(this.serializer.serialize(any(), any())).thenAnswer((invocation -> {
            DocumentReference reference = invocation.getArgument(0);
            StringBuilder sb = new StringBuilder();
            for (EntityReference entityReference : reference.getReversedReferenceChain()) {
                sb.append(entityReference.getName());
                if (entityReference instanceof WikiReference) {
                    sb.append(":");
                } else {
                    sb.append(".");
                }
            }
            return sb.substring(0, sb.length() - 1);
        }));

        when(this.contextProvider.get()).thenReturn(this.context);
        when(this.context.getWikiId()).thenReturn(WIKI_ID);
        when(this.context.getMainXWiki()).thenReturn(WIKI_ID);
        when(this.context.getWiki()).thenReturn(this.xWiki);
        when(this.xWiki.getDocument(eq(REF_GROUP), any())).thenReturn(this.groupDocument);

        when(this.xWiki.getGroupClass(this.context)).thenReturn(this.groupClass);
        when(this.groupClass.getDocumentReference()).thenReturn(REF_GROUP);
        when(this.groupDocument.newXObject(any(), eq(this.context))).thenReturn(this.groupObject);

        when(this.xwikiLDAPConfigProvider.get()).thenReturn(ldapConfig);
        when(this.xWikiLDAPFactory.getLDAPConnection(this.ldapConfig)).thenReturn(this.xWikiLDAPConnection);
        when(this.xWikiLDAPFactory.getLDAPUtils(this.xWikiLDAPConnection, this.ldapConfig)).thenReturn(
            this.xWikiLDAPUtils);
        when(this.xWikiLDAPFactory.getLDAPProfileXClass(this.context)).thenReturn(this.ldapProfileXClass);

        when(this.xWikiLDAPUtils.searchUserAttributesByUid(any(), any())).thenAnswer((invocation -> {
            String uid = invocation.getArgument(0);
            String[] attrNameTable = invocation.getArgument(1);
            Set<String> attrs = new HashSet<>(Arrays.asList(attrNameTable));
            attrs.add("dn");
            return attrs.stream().map(attr -> {
                if (attr.equals("uid")) {
                    return new XWikiLDAPSearchAttribute(attr, uid);
                } else {
                    return new XWikiLDAPSearchAttribute(attr, uid + attr);
                }
            }).collect(
                Collectors.toList());
        }));
        when(this.xWikiLDAPUtils.getUserPageName(any(), any())).thenAnswer((invocation) -> {
            List<XWikiLDAPSearchAttribute> attrs = invocation.getArgument(0);
            return attrs.get(0).value;
        });

        when(this.xWikiLDAPConnection.searchPaginated(any(String.class), anyInt(), any(String.class),
            any(String[].class), anyBoolean())).thenReturn(this.searchResults);
        AtomicInteger atomicInteger = new AtomicInteger(0);
        when(this.searchResults.hasMore()).thenAnswer((inv) -> {
            if (atomicInteger.getAndIncrement() == 0) {
                return true;
            } else {
                return false;
            }
        });
        when(this.searchResults.next()).thenAnswer((invocation -> {
            if (atomicInteger.getAndIncrement() == 0) {
                LDAPAttributeSet attributeSet = new LDAPAttributeSet();
                attributeSet.add("somethin");
                return new LDAPEntry("user1", attributeSet);
            } else {
                throw new LDAPException();
            }
        }));
    }

    @Test
    void importSingleUserTest() throws Exception
    {
        when(this.xWiki.exists(any(DocumentReference.class), any())).thenReturn(true);

        testUsersImport(new String[] { "user1" }, XWIKI_GROUP, () -> {
            String[] users = new String[] { "user1" };

            try {
                defaultLDAPUserImportManager.importUsers(users, XWIKI_GROUP);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, true);
    }

    @Test
    void updateGroupWithOneNewUsersTest() throws Exception
    {
        when(this.xWikiLDAPUtils.getGroupMembers("ldapgroup", this.context)).thenReturn(Map.of("XWiki.User1", "user1"));
        when(this.xWiki.getDocument(XWIKI_GROUP, this.context)).thenReturn(this.groupDocument);

        when(this.xWiki.exists(eq(new DocumentReference(WIKI_ID, XWIKI_GROUP, "user1")), eq(this.context))).thenReturn(
            false);
        when(this.ldapProfileXClass.getDn(any(XWikiDocument.class))).thenReturn("something");
        when(this.groupDocument.getXObject(any(DocumentReference.class), eq("member"), any())).thenReturn(
            this.groupObject);

        // Update group calls defaultLDAPUserImportManager#importUsers.
        testUsersImport(new String[] { "user1" }, XWIKI_GROUP, () -> {
            try {
                defaultLDAPUserImportManager.updateGroup(XWIKI_GROUP);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, false);

        verify(this.groupClass, times(1)).fromMap(any(Map.class), any(BaseObject.class));
        verify(this.xWiki).saveDocument(this.groupDocument, this.context);
    }

    @Test
    void updateGroupWithUsersRemovedFromLDAPGroupsTest() throws XWikiException
    {
        when(this.xWikiLDAPUtils.getGroupMembers("ldapgroup", this.context))
            .thenReturn(Map.of("user1dn", "user1", "user2dn", "user2", "user3dn", "user3"));
        when(this.xWiki.getDocument(XWIKI_GROUP, this.context)).thenReturn(this.groupDocument);

        when(this.xWiki.exists(eq(new DocumentReference(WIKI_ID, XWIKI_GROUP, "user1")), eq(this.context))).thenReturn(
            false);
        when(this.xWiki.exists(eq(new DocumentReference(WIKI_ID, XWIKI_GROUP, "user2")), eq(this.context))).thenReturn(
            false);
        when(this.xWiki.exists(eq(new DocumentReference(WIKI_ID, XWIKI_GROUP, "user3")), eq(this.context))).thenReturn(
            false);

        BaseObject existingGroupUser = mock(BaseObject.class);
        when(this.groupDocument.getXObjects(any(DocumentReference.class))).thenReturn(
            Collections.singletonList(existingGroupUser));
        when(this.groupDocument.getXObjects(any(EntityReference.class))).thenReturn(
            Collections.singletonList(existingGroupUser));
        when(existingGroupUser.getStringValue("member")).thenReturn("xwiki:XWiki.user4");

        when(this.ldapProfileXClass.getDn(any(XWikiDocument.class))).thenReturn("something");
        when(this.groupDocument.getXObject(any(DocumentReference.class), eq("member"), any())).thenReturn(
            this.groupObject);

        XWikiDocument existingGroupUserDoc = mock(XWikiDocument.class);
        when(this.xWiki.getDocument(eq(new DocumentReference(WIKI_ID, MAIN_SPACE, "user4")),
            eq(this.context))).thenReturn(
            existingGroupUserDoc);
        when(this.ldapProfileXClass.getDn(existingGroupUserDoc)).thenReturn("smth");
        when(this.groupDocument.getXObject(any(), eq("member"), eq("xwiki:XWiki.user4"))).thenReturn(existingGroupUser);

        // Update group calls defaultLDAPUserImportManager#importUsers.
        testUsersImport(new String[] { "user1", "user2", "user3" }, XWIKI_GROUP, () -> {
            try {
                defaultLDAPUserImportManager.updateGroup(XWIKI_GROUP);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, false);

        verify(this.groupClass, times(3)).fromMap(any(Map.class), any(BaseObject.class));
        verify(this.xWiki).saveDocument(this.groupDocument, this.context);
        verify(this.groupDocument).removeXObject(eq(existingGroupUser));
    }

    /**
     * If one user fails to get imported, the others should be processed.
     */
    @Test
    void updateGroupAndOneUserFailsTest() throws XWikiException
    {
        String[] users = new String[3];
        for (int i = 0; i < users.length; i++) {
            users[i] = "user" + i;
        }
        Map<String, String> usersMap = new HashMap<>();
        for (String user : users) {
            usersMap.put("XWiki." + user, user);
        }
        when(this.xWikiLDAPUtils.getGroupMembers("ldapgroup", this.context)).thenReturn(usersMap);
        when(this.xWiki.getDocument(XWIKI_GROUP, this.context)).thenReturn(this.groupDocument);

        when(this.xWiki.exists(any(DocumentReference.class), eq(this.context))).thenReturn(false);
        when(this.ldapProfileXClass.getDn(any(XWikiDocument.class))).thenReturn("something");
        when(this.groupDocument.getXObject(any(DocumentReference.class), eq("member"), any())).thenReturn(
            this.groupObject);

        // Update group calls defaultLDAPUserImportManager#importUsers.
        testUsersImport(users, XWIKI_GROUP, () -> {
            try {
                when(this.xWikiLDAPUtils.syncUser(any(), any(), any(), eq("user0"), any())).thenThrow(
                    XWikiException.class);
            } catch (XWikiException ignored) {
            }
            try {
                defaultLDAPUserImportManager.updateGroup(XWIKI_GROUP);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, false);

        verify(this.logger).error(anyString(), any(), any());
        verify(this.xWiki).getDocument(eq(new DocumentReference("xwiki", "XWiki", "user1")), any(XWikiContext.class));
        verify(this.xWiki).getDocument(eq(new DocumentReference("xwiki", "XWiki", "user2")), any(XWikiContext.class));
        verify(this.xWiki, never()).getDocument(eq(new DocumentReference("xwiki", "XWiki", "user0")),
            any(XWikiContext.class));
        verify(this.xWiki, times(1)).saveDocument(this.groupDocument, this.context);
    }

    @Test
    void updateGroupWithOver500UsersTest() throws XWikiException
    {
        String[] users = new String[501];
        for (int i = 0; i < users.length; i++) {
            users[i] = "user" + i;
        }
        Map<String, String> usersMap = new HashMap<>();
        for (String user : users) {
            usersMap.put("XWiki." + user, user);
        }
        when(this.xWikiLDAPUtils.getGroupMembers("ldapgroup", this.context)).thenReturn(usersMap);
        when(this.xWiki.getDocument(XWIKI_GROUP, this.context)).thenReturn(this.groupDocument);

        when(this.xWiki.exists(any(DocumentReference.class), eq(this.context))).thenReturn(false);
        when(this.ldapProfileXClass.getDn(any(XWikiDocument.class))).thenReturn("something");
        when(this.groupDocument.getXObject(any(DocumentReference.class), eq("member"), any())).thenReturn(
            this.groupObject);

        // Update group calls defaultLDAPUserImportManager#importUsers.
        testUsersImport(users, XWIKI_GROUP, () -> {
            try {
                defaultLDAPUserImportManager.updateGroup(XWIKI_GROUP);
            } catch (Exception e) {
                throw new RuntimeException(e);
            }
        }, false);

        verify(this.groupClass, times(501)).fromMap(any(Map.class), any(BaseObject.class));
        verify(this.xWiki, times(2)).saveDocument(this.groupDocument, this.context);
    }

    private void testUsersImport(String[] users, String group, Runnable runnable, boolean addUsersInGroup)
        throws XWikiException
    {
        List<Runnable> verifies = new ArrayList<>();
        for (String user : users) {
            User apiUser = mock(User.class);
            when(this.xWiki.getUser(any(String.class), eq(this.context))).thenReturn(apiUser);

            XWikiDocument userDoc = mock(XWikiDocument.class);
            DocumentReference userRef = new DocumentReference(WIKI_ID, MAIN_SPACE, user);
            BaseObject userObj = mock(BaseObject.class);
            BaseObject clonedUserObj = mock(BaseObject.class);
            when(userDoc.getXObject(any(DocumentReference.class), anyBoolean(),
                any(XWikiContext.class))).thenReturn(userObj);

            when(userDoc.getDocumentReference()).thenReturn(userRef);
            when(userObj.clone()).thenReturn(clonedUserObj);

            when(this.xWikiLDAPUtils.syncUser(any(), any(), any(), eq(user), any())).thenReturn(userDoc);
            when(this.xWiki.getDocument(new DocumentReference(WIKI_ID, MAIN_SPACE, user), this.context)).thenReturn(
                userDoc);

            when(apiUser.isUserInGroup(any())).thenReturn(false);
            when(this.xWiki.getDocument(eq(userRef), any())).thenReturn(userDoc);

            verifies.add(() -> {
                try {

                    verify(this.xWikiLDAPUtils).syncUser(any(), any(), any(), eq(user), eq(this.context));

                    if (addUsersInGroup) {
                        verify(userObj, times(2)).setStringValue(any(String.class), any(String.class));
                        verify(this.xWiki).saveDocument(eq(userDoc), any(String.class), eq(this.context));
                        verify(this.groupObject).setStringValue(eq("member"), eq("xwiki:XWiki." + user));
                        verify(this.xWiki).saveDocument(eq(this.groupDocument), any(String.class), eq(this.context));
                    }
                } catch (XWikiException e) {
                    throw new RuntimeException(e);
                }
            });
        }
        runnable.run();
        for (Runnable verify : verifies) {
            verify.run();
        }
    }
}
