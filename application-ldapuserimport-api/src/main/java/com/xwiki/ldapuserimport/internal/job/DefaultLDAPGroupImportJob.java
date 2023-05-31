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
package com.xwiki.ldapuserimport.internal.job;

import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.inject.Named;
import javax.inject.Provider;

import org.xwiki.component.annotation.Component;
import org.xwiki.contrib.ldap.LDAPDocumentHelper;
import org.xwiki.contrib.ldap.XWikiLDAPConfig;
import org.xwiki.contrib.ldap.XWikiLDAPException;
import org.xwiki.contrib.ldap.XWikiLDAPSearchAttribute;
import org.xwiki.job.event.status.JobProgressManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.model.reference.EntityReferenceSerializer;
import org.xwiki.wiki.descriptor.WikiDescriptorManager;

import com.xpn.xwiki.XWiki;
import com.xpn.xwiki.XWikiContext;
import com.xpn.xwiki.XWikiException;
import com.xpn.xwiki.doc.XWikiDocument;
import com.xwiki.ldapuserimport.LDAPGroupImportManager;
import com.xwiki.ldapuserimport.LDAPUserImportManager;
import com.xwiki.ldapuserimport.internal.XWikiLDAPUtilsHelper;
import com.xwiki.ldapuserimport.job.AbstractLDAPGroupImportJob;

/**
 * Default implementation of the {@link AbstractLDAPGroupImportJob}.
 *
 * @version $Id$
 * @since 1.4
 */
@Component
@Named(AbstractLDAPGroupImportJob.JOB_TYPE)
public class DefaultLDAPGroupImportJob extends AbstractLDAPGroupImportJob
{
    @Inject
    private EntityReferenceSerializer<String> stringEntityReferenceSerializer;

    @Inject
    private JobProgressManager jobProgressManager;

    @Inject
    private LDAPDocumentHelper ldapDocumentHelper;

    @Inject
    private LDAPGroupImportManager ldapGroupImportManager;

    @Inject
    private LDAPUserImportManager ldapUserImportManager;

    @Inject
    private Provider<XWikiLDAPConfig> xWikiLDAPConfigProvider;

    @Inject
    private Provider<XWikiContext> xWikiContextProvider;

    @Inject
    private WikiDescriptorManager wikiDescriptorManager;

    @Override
    public String getType()
    {
        return JOB_TYPE;
    }

    @Override
    protected void runInternal() throws Exception
    {
        // Start by getting the list of available LDAP groups from the LDAP directory
        jobProgressManager.startStep(this, "Retrieve the list of importable groups");
        Map<String, List<XWikiLDAPSearchAttribute>> importableGroups = ldapGroupImportManager.getImportableGroups(
            request.getLDAPGroupSearchDN(), request.getLDAPGroupSearchFilter(), request.getLDAPGroupSearchAttributes());
        jobProgressManager.endStep(this);

        // Exclude every LDAP group already mapped to an XWiki group
        jobProgressManager.startStep(this, "Exclude existing linked groups");
        Map<String, Set<String>> mappings = xWikiLDAPConfigProvider.get().getGroupMappings();
        for (Map.Entry<String, Set<String>> mapping : mappings.entrySet()) {
            for (String existingLDAPGroup : mapping.getValue()) {
                importableGroups.remove(existingLDAPGroup);
            }
        }
        jobProgressManager.endStep(this);

        // With the remaining groups, compute their XWiki group name, create a document, and register them as bindings
        jobProgressManager.startStep(this, "Create new groups and register their mappings");
        jobProgressManager.pushLevelProgress(importableGroups.size(), this);
        logger.info("[{}] LDAP groups will be imported", importableGroups.size());

        for (Map.Entry<String, List<XWikiLDAPSearchAttribute>> importableGroup : importableGroups.entrySet()) {
            jobProgressManager.startStep(this);
            String xwikiGroupName = ldapDocumentHelper.getDocumentName(request.getGroupPageName(),
                XWikiLDAPUtilsHelper.CN, importableGroup.getValue(), xWikiLDAPConfigProvider.get());

            try {
                DocumentReference xwikiGroupReference = new DocumentReference(wikiDescriptorManager.getCurrentWikiId(),
                    XWiki.SYSTEM_SPACE, xwikiGroupName);

                createXWikiGroupDocument(xwikiGroupReference);
                ldapUserImportManager.associateGroups(new String[] { importableGroup.getKey() },
                    stringEntityReferenceSerializer.serialize(xwikiGroupReference));

                status.addImportedGroup(xwikiGroupReference);
                logger.info("Successfully imported LDAP group [{}] as [{}]", importableGroup, xwikiGroupReference);
            } catch (Exception e) {
                logger.error("Failed to import LDAP group [{}] as [{}]", importableGroup, xwikiGroupName, e);
            }
            jobProgressManager.endStep(this);
        }

        jobProgressManager.popLevelProgress(this);
        jobProgressManager.endStep(this);
    }

    private void createXWikiGroupDocument(DocumentReference groupReference) throws XWikiException
    {
        XWikiContext context = xWikiContextProvider.get();
        XWiki xwiki = context.getWiki();
        XWikiDocument groupDocument = xwiki.getDocument(groupReference, context);

        // Make sure that the document is new, even this should have been handled beforehand
        // TODO: Define an exception specific to the LDAP User import module and use it here. Currently, it's not a
        //  big issue as we don't expose this code as API
        if (!groupDocument.isNew()) {
            throw new XWikiLDAPException(String.format("The group document [%s] already exists.", groupReference));
        }

        groupDocument.createXObject(new DocumentReference(wikiDescriptorManager.getCurrentWikiId(),
            XWiki.SYSTEM_SPACE, "XWikiGroups"), context);

        xwiki.saveDocument(groupDocument,
            String.format("Automated creation from LDAP group [%s]", groupReference), context);
    }
}
