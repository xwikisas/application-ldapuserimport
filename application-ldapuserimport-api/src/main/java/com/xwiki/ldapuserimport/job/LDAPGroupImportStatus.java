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
package com.xwiki.ldapuserimport.job;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import org.xwiki.job.DefaultJobStatus;
import org.xwiki.job.event.status.JobStatus;
import org.xwiki.logging.LoggerManager;
import org.xwiki.model.reference.DocumentReference;
import org.xwiki.observation.ObservationManager;
import org.xwiki.stability.Unstable;

/**
 * Status for the LDAP Group Import Job.
 *
 * @version $Id$
 * @since 1.4
 */
@Unstable
public class LDAPGroupImportStatus extends DefaultJobStatus<LDAPGroupImportRequest>
{
    private List<DocumentReference> importedGroups = new ArrayList<>();

    /**
     * Create a new {@link LDAPGroupImportStatus}.
     *
     * @see DefaultJobStatus
     * @param jobType the job type
     * @param request the request
     * @param parentJobStatus the parent job status
     * @param observationManager the observation manager
     * @param loggerManager the logger manager
     */
    public LDAPGroupImportStatus(String jobType, LDAPGroupImportRequest request, JobStatus parentJobStatus,
        ObservationManager observationManager, LoggerManager loggerManager)
    {
        super(jobType, request, parentJobStatus, observationManager, loggerManager);
    }

    /**
     * @return a list of imported groups
     */
    public List<DocumentReference> getImportedGroups()
    {
        return Collections.unmodifiableList(importedGroups);
    }

    /**
     * Adds a new group to the list of imported groups.
     *
     * @param groupReference the group to add
     */
    public void addImportedGroup(DocumentReference groupReference)
    {
        this.importedGroups.add(groupReference);
    }
}
