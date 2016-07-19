/*-
 * Copyright (c) 2011-2012 George V. Neville-Neil,
 *                         Steven Kreuzer, 
 *                         Martin Burnicki, 
 *                         Jan Breuer,
 *                         Gael Mace, 
 *                         Alexandre Van Kempen,
 *                         Inaqui Delgado,
 *                         Rick Ratzel,
 *                         National Instruments.
 * Copyright (c) 2009-2010 George V. Neville-Neil, 
 *                         Steven Kreuzer, 
 *                         Martin Burnicki, 
 *                         Jan Breuer,
 *                         Gael Mace, 
 *                         Alexandre Van Kempen
 *
 * Copyright (c) 2005-2008 Kendall Correll, Aidan Williams
 *
 * All Rights Reserved
 * 
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are
 * met:
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 
 * THIS SOFTWARE IS PROVIDED BY THE AUTHORS ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE AUTHORS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/**
 * @file   bmc.c
 * @date   Wed Jun 23 09:36:09 2010
 * 
 * @brief  Best master clock selection code.
 * 
 * The functions in this file are used by the daemon to select the
 * best master clock from any number of possibilities.
 */

#include "ptpd.h"


/* Init ptpClock with run time values (initialization constants are in constants.h)*/
void initData(RunTimeOpts *rtOpts, PtpClock *ptpClock)
{
	int i,j;
	j=0;
	DBG("initData\n");
	
	/* Default data set */
	ptpClock->twoStepFlag = TWO_STEP_FLAG;

	/*
	 * init clockIdentity with MAC address and 0xFF and 0xFE. see
	 * spec 7.5.2.2.2
	 */
	for (i=0;i<CLOCK_IDENTITY_LENGTH;i++)
	{
		if (i==3) ptpClock->clockIdentity[i]=0xFF;
		else if (i==4) ptpClock->clockIdentity[i]=0xFE;
		else
		{
		  ptpClock->clockIdentity[i]=ptpClock->netPath.port_uuid_field[j];
		  j++;
		}
	}
	ptpClock->numberPorts = NUMBER_PORTS;

	ptpClock->clockQuality.clockAccuracy = 
		rtOpts->clockQuality.clockAccuracy;
	ptpClock->clockQuality.clockClass = rtOpts->clockQuality.clockClass;
	ptpClock->clockQuality.offsetScaledLogVariance = 
		rtOpts->clockQuality.offsetScaledLogVariance;

	ptpClock->priority1 = rtOpts->priority1;
	ptpClock->priority2 = rtOpts->priority2;

	ptpClock->domainNumber = rtOpts->domainNumber;
	if(rtOpts->slaveOnly) {
		ptpClock->slaveOnly = TRUE;
		rtOpts->clockQuality.clockClass = SLAVE_ONLY_CLOCK_CLASS;
	}

/* Port configuration data set */

	/*
	 * PortIdentity Init (portNumber = 1 for an ardinary clock spec
	 * 7.5.2.3)
	 */
	copyClockIdentity(ptpClock->portIdentity.clockIdentity,
			ptpClock->clockIdentity);
	ptpClock->portIdentity.portNumber = NUMBER_PORTS;

	/* select the initial rate of delayreqs until we receive the first announce message */

	ptpClock->logMinDelayReqInterval = rtOpts->initial_delayreq;

	clearTime(&ptpClock->peerMeanPathDelay);

	ptpClock->logAnnounceInterval = rtOpts->announceInterval;
	ptpClock->announceReceiptTimeout = rtOpts->announceReceiptTimeout;
	ptpClock->logSyncInterval = rtOpts->syncInterval;
	ptpClock->delayMechanism = rtOpts->delayMechanism;
	ptpClock->logMinPdelayReqInterval = rtOpts->logMinPdelayReqInterval;
	ptpClock->versionNumber = VERSION_PTP;

 	/*
	 *  Initialize random number generator using same method as ptpv1:
	 *  seed is now initialized from the last bytes of our mac addres (collected in net.c:findIface())
	 */
	srand((ptpClock->netPath.port_uuid_field[PTP_UUID_LENGTH - 1] << 8) +
	    ptpClock->netPath.port_uuid_field[PTP_UUID_LENGTH - 2]);

	/*Init other stuff*/
	ptpClock->number_foreign_records = 0;
  	ptpClock->max_foreign_records = rtOpts->max_foreign_records;
}


/*Local clock is becoming Master. Table 13 (9.3.5) of the spec.*/
void m1(const RunTimeOpts *rtOpts, PtpClock *ptpClock)
{
	/*Current data set update*/
	ptpClock->stepsRemoved = 0;
	
	clearTime(&ptpClock->offsetFromMaster);
	clearTime(&ptpClock->meanPathDelay);

	copyClockIdentity(ptpClock->parentPortIdentity.clockIdentity,
	       ptpClock->clockIdentity);

	ptpClock->parentPortIdentity.portNumber = ptpClock->numberPorts;
	ptpClock->parentStats = DEFAULT_PARENTS_STATS;
	ptpClock->observedParentClockPhaseChangeRate = 0;
	ptpClock->observedParentOffsetScaledLogVariance = 0;
	copyClockIdentity(ptpClock->grandmasterIdentity,
			ptpClock->clockIdentity);
	ptpClock->grandmasterClockQuality.clockAccuracy = 
		ptpClock->clockQuality.clockAccuracy;
	ptpClock->grandmasterClockQuality.clockClass = 
		ptpClock->clockQuality.clockClass;
	ptpClock->grandmasterClockQuality.offsetScaledLogVariance = 
		ptpClock->clockQuality.offsetScaledLogVariance;
	ptpClock->grandmasterPriority1 = ptpClock->priority1;
	ptpClock->grandmasterPriority2 = ptpClock->priority2;
        ptpClock->logMinDelayReqInterval = rtOpts->subsequent_delayreq;

	/*Time Properties data set*/
	ptpClock->timePropertiesDS.currentUtcOffsetValid = rtOpts->timeProperties.currentUtcOffsetValid;
	ptpClock->timePropertiesDS.currentUtcOffset = rtOpts->timeProperties.currentUtcOffset;
	ptpClock->timePropertiesDS.timeTraceable = rtOpts->timeProperties.timeTraceable;
	ptpClock->timePropertiesDS.frequencyTraceable = rtOpts->timeProperties.frequencyTraceable;
	ptpClock->timePropertiesDS.ptpTimescale = rtOpts->timeProperties.ptpTimescale;
	ptpClock->timePropertiesDS.timeSource = rtOpts->timeProperties.timeSource;
}


/* first cut on a passive mode specific BMC actions */
void p1(PtpClock *ptpClock, const RunTimeOpts *rtOpts)
{
	/* make sure we revert to ARB timescale in Passive mode*/
	if(ptpClock->portState == PTP_PASSIVE){
		ptpClock->timePropertiesDS.currentUtcOffsetValid = rtOpts->timeProperties.currentUtcOffsetValid;
		ptpClock->timePropertiesDS.currentUtcOffset = rtOpts->timeProperties.currentUtcOffset;
	}
	
}


/*Local clock is synchronized to Ebest Table 16 (9.3.5) of the spec*/
void s1(MsgHeader *header,MsgAnnounce *announce,PtpClock *ptpClock, const RunTimeOpts *rtOpts)
{

	Boolean previousLeap59 = FALSE, previousLeap61 = FALSE;
	Integer16 previousUtcOffset = 0;

	if (ptpClock->portState == PTP_SLAVE || ptpClock->portState==PTP_PASSIVE) {
		previousLeap59 = ptpClock->timePropertiesDS.leap59;
		previousLeap61 = ptpClock->timePropertiesDS.leap61;
		previousUtcOffset = ptpClock->timePropertiesDS.currentUtcOffset;
	}

	/* Current DS */
	ptpClock->stepsRemoved = announce->stepsRemoved + 1;

	/* Parent DS */
	copyClockIdentity(ptpClock->parentPortIdentity.clockIdentity,
	       header->sourcePortIdentity.clockIdentity);
	ptpClock->parentPortIdentity.portNumber = 
		header->sourcePortIdentity.portNumber;
	copyClockIdentity(ptpClock->grandmasterIdentity,
			announce->grandmasterIdentity);
	ptpClock->grandmasterClockQuality.clockAccuracy = 
		announce->grandmasterClockQuality.clockAccuracy;
	ptpClock->grandmasterClockQuality.clockClass = 
		announce->grandmasterClockQuality.clockClass;
	ptpClock->grandmasterClockQuality.offsetScaledLogVariance = 
		announce->grandmasterClockQuality.offsetScaledLogVariance;
	ptpClock->grandmasterPriority1 = announce->grandmasterPriority1;
	ptpClock->grandmasterPriority2 = announce->grandmasterPriority2;

	ptpClock->logAnnounceInterval = header->logMessageInterval;

	/* Timeproperties DS */
	ptpClock->timePropertiesDS.currentUtcOffset = announce->currentUtcOffset;

	if (ptpClock->portState != PTP_PASSIVE && ptpClock->timePropertiesDS.currentUtcOffsetValid && 
			!IS_SET(header->flagField1, UTCV)) {
		if(rtOpts->alwaysRespectUtcOffset)
			WARNING("UTC Offset no longer valid and ptpengine:always_respect_utc_offset is set: continuing as normal\n");
		else
			WARNING("UTC Offset no longer valid - clock jump expected\n");
	}

        /* "Valid" is bit 2 in second octet of flagfield */
        ptpClock->timePropertiesDS.currentUtcOffsetValid = IS_SET(header->flagField1, UTCV);

	/* set PTP_PASSIVE-specific state */
	p1(ptpClock, rtOpts);

	/* only set leap state in slave mode */
	if (ptpClock->portState == PTP_SLAVE) {
		ptpClock->timePropertiesDS.leap59 = IS_SET(header->flagField1, LI59);
		ptpClock->timePropertiesDS.leap61 = IS_SET(header->flagField1, LI61);
	}

        ptpClock->timePropertiesDS.timeTraceable = IS_SET(header->flagField1, TTRA);
        ptpClock->timePropertiesDS.frequencyTraceable = IS_SET(header->flagField1, FTRA);
        ptpClock->timePropertiesDS.ptpTimescale = IS_SET(header->flagField1, PTPT);
        ptpClock->timePropertiesDS.timeSource = announce->timeSource;

#ifndef FSL_1588
#if defined(MOD_TAI) &&  NTP_API == 4
	/*
	 * update kernel TAI offset, but only if timescale is
	 * PTP not ARB - spec section 7.2
	 */
        if (ptpClock->timePropertiesDS.ptpTimescale &&
	    (ptpClock->timePropertiesDS.currentUtcOffsetValid || rtOpts->alwaysRespectUtcOffset) &&
            (ptpClock->timePropertiesDS.currentUtcOffset != previousUtcOffset)) {
		setKernelUtcOffset(ptpClock->timePropertiesDS.currentUtcOffset);
		INFO("Set kernel UTC offset to %d\n", ptpClock->timePropertiesDS.currentUtcOffset);
        }
#endif /* MOD_TAI */
#endif /* FSL_1588 */

	/* Leap second handling */

        if (ptpClock->portState == PTP_SLAVE) {
		if(ptpClock->timePropertiesDS.leap59 && ptpClock->timePropertiesDS.leap61) {
			DBG("Both Leap59 and Leap61 flags set!\n");
			ptpClock->counters.protocolErrors++;
			return;
		}

		/* one of the leap second flags has suddenly been unset */
		if(ptpClock->leapSecondPending && 
		    !ptpClock->leapSecondInProgress &&
		    ((previousLeap59 != ptpClock->timePropertiesDS.leap59) || 
		     (previousLeap61 != ptpClock->timePropertiesDS.leap61))) {
			WARNING("Leap second event aborted by GM!");
			ptpClock->leapSecondPending = FALSE;
			ptpClock->leapSecondInProgress = FALSE;
			timerStop(LEAP_SECOND_PAUSE_TIMER, ptpClock->itimer);
#ifndef FSL_1588
#if !defined(__APPLE__)
			unsetTimexFlags(STA_INS | STA_DEL,TRUE);
#endif /* apple */
#endif /* FSL_1588 */
		}

		/*
		 * one of the leap second flags has been set
		 * or flags are lit but we have no event pending
		 */
		if( (ptpClock->timePropertiesDS.leap59 || ptpClock->timePropertiesDS.leap61) && (
		    (!ptpClock->leapSecondPending && 
		    !ptpClock->leapSecondInProgress ) ||
		    ((!previousLeap59 && ptpClock->timePropertiesDS.leap59) ||
		    (!previousLeap61 && ptpClock->timePropertiesDS.leap61)))) {
#ifndef FSL_1588
#if !defined(__APPLE__)
			WARNING("Leap second pending! Setting kernel to %s "
				"one second at midnight\n",
				ptpClock->timePropertiesDS.leap61 ? "add" : "delete");
		    if (!checkTimexFlags(ptpClock->timePropertiesDS.leap61 ? STA_INS : STA_DEL)) {
			    unsetTimexFlags(ptpClock->timePropertiesDS.leap61 ? STA_DEL : STA_INS,
					    TRUE);
			    setTimexFlags(ptpClock->timePropertiesDS.leap61 ? STA_INS : STA_DEL,
					  FALSE);
		    }
#else
			WARNING("Leap second pending! No kernel leap second "
				"API support - expect a clock jump at "
				"midnight!\n");
#endif /* apple */
#endif /* FSL_1588 */
			/* only set the flag, the rest happens in doState() */
			ptpClock->leapSecondPending = TRUE;
		}

		if((previousUtcOffset != ptpClock->timePropertiesDS.currentUtcOffset) && 
		   !ptpClock->leapSecondPending && 
		   !ptpClock->leapSecondInProgress ) {
			WARNING("UTC offset changed from %d to %d with "
				"no leap second pending!\n",
				previousUtcOffset, ptpClock->timePropertiesDS.currentUtcOffset);
		} else if( previousUtcOffset != ptpClock->timePropertiesDS.currentUtcOffset) {
			WARNING("UTC offset changed from %d to %d\n",
				previousUtcOffset,ptpClock->timePropertiesDS.currentUtcOffset);
		}
	}
}


/*Copy local data set into header and announce message. 9.3.4 table 12*/
static void
copyD0(MsgHeader *header, MsgAnnounce *announce, PtpClock *ptpClock)
{
	announce->grandmasterPriority1 = ptpClock->priority1;
	copyClockIdentity(announce->grandmasterIdentity,
			ptpClock->clockIdentity);
	announce->grandmasterClockQuality.clockClass = 
		ptpClock->clockQuality.clockClass;
	announce->grandmasterClockQuality.clockAccuracy = 
		ptpClock->clockQuality.clockAccuracy;
	announce->grandmasterClockQuality.offsetScaledLogVariance = 
		ptpClock->clockQuality.offsetScaledLogVariance;
	announce->grandmasterPriority2 = ptpClock->priority2;
	announce->stepsRemoved = 0;
	copyClockIdentity(header->sourcePortIdentity.clockIdentity,
	       ptpClock->clockIdentity);

	/* Copy TimePropertiesDS into FlagField1 */
        header->flagField1 = ptpClock->timePropertiesDS.leap61			<< 0;
        header->flagField1 |= ptpClock->timePropertiesDS.leap59			<< 1;
        header->flagField1 |= ptpClock->timePropertiesDS.currentUtcOffsetValid	<< 2;
        header->flagField1 |= ptpClock->timePropertiesDS.ptpTimescale		<< 3;
        header->flagField1 |= ptpClock->timePropertiesDS.timeTraceable		<< 4;
        header->flagField1 |= ptpClock->timePropertiesDS.frequencyTraceable	<< 5;

}


/*Data set comparison bewteen two foreign masters (9.3.4 fig 27)
 * return similar to memcmp() */

static Integer8 
bmcDataSetComparison(const MsgHeader *headerA, const MsgAnnounce *announceA,
		     const MsgHeader *headerB, const MsgAnnounce *announceB,
		     const PtpClock *ptpClock, const RunTimeOpts * rtOpts)
{
	DBGV("Data set comparison \n");
	short comp = 0;
	/*Identity comparison*/
	comp = memcmp(announceA->grandmasterIdentity,announceB->grandmasterIdentity,CLOCK_IDENTITY_LENGTH);

	if (comp!=0)
		goto dataset_comp_part_1;

	  /* Algorithm part2 Fig 28 */
	if (announceA->stepsRemoved > announceB->stepsRemoved+1)
		return 1;
	if (announceA->stepsRemoved+1 < announceB->stepsRemoved)
		return -1;

	/* A within 1 of B */

	if (announceA->stepsRemoved > announceB->stepsRemoved) {
		comp = memcmp(headerA->sourcePortIdentity.clockIdentity,ptpClock->parentPortIdentity.clockIdentity,CLOCK_IDENTITY_LENGTH);
		if(comp < 0)
			return -1;
		if(comp > 0)
			return 1;
		DBG("Sender=Receiver : Error -1");
		return 0;
	}

	if (announceA->stepsRemoved < announceB->stepsRemoved) {
		comp = memcmp(headerB->sourcePortIdentity.clockIdentity,ptpClock->parentPortIdentity.clockIdentity,CLOCK_IDENTITY_LENGTH);

		if(comp < 0)
			return -1;
		if(comp > 0)
			return 1;
		DBG("Sender=Receiver : Error -1");
		return 0;
	}
	/*  steps removed A = steps removed B */
	comp = memcmp(headerA->sourcePortIdentity.clockIdentity,headerB->sourcePortIdentity.clockIdentity,CLOCK_IDENTITY_LENGTH);

	if (comp<0) {
		return -1;
	}

	if (comp>0) {
		return 1;
	}

	/* identity A = identity B */

	if (headerA->sourcePortIdentity.portNumber < headerB->sourcePortIdentity.portNumber)
		return -1;
	if (headerA->sourcePortIdentity.portNumber > headerB->sourcePortIdentity.portNumber)
		return 1;

	DBG("Sender=Receiver : Error -2");
	return 0;

	  /* Algorithm part 1 Fig 27 */
dataset_comp_part_1:

	/* Compare GM priority1 */
	if (announceA->grandmasterPriority1 < announceB->grandmasterPriority1)
		return -1;
	if (announceA->grandmasterPriority1 > announceB->grandmasterPriority1)
		return 1;

	/* non-standard BMC extension to prioritise GMs with UTC valid */
	if(rtOpts->preferUtcValid) {
		Boolean utcA = IS_SET(headerA->flagField1, UTCV);
		Boolean utcB = IS_SET(headerB->flagField1, UTCV);
		if(utcA > utcB)
			return -1;
		if(utcA < utcB)
			return 1;
	}

	/* Compare GM class */
	if (announceA->grandmasterClockQuality.clockClass <
			announceB->grandmasterClockQuality.clockClass)
		return -1;
	if (announceA->grandmasterClockQuality.clockClass >
			announceB->grandmasterClockQuality.clockClass)
		return 1;
	
	/* Compare GM accuracy */
	if (announceA->grandmasterClockQuality.clockAccuracy <
			announceB->grandmasterClockQuality.clockAccuracy)
		return -1;
	if (announceA->grandmasterClockQuality.clockAccuracy >
			announceB->grandmasterClockQuality.clockAccuracy)
		return 1;

	/* Compare GM offsetScaledLogVariance */
	if (announceA->grandmasterClockQuality.offsetScaledLogVariance <
			announceB->grandmasterClockQuality.offsetScaledLogVariance)
		return -1;
	if (announceA->grandmasterClockQuality.offsetScaledLogVariance >
			announceB->grandmasterClockQuality.offsetScaledLogVariance)
		return 1;
	
	/* Compare GM priority2 */
	if (announceA->grandmasterPriority2 < announceB->grandmasterPriority2)
		return -1;
	if (announceA->grandmasterPriority2 > announceB->grandmasterPriority2)
		return 1;

	/* Compare GM identity */
	if (comp < 0)
		return -1;
	else if (comp > 0)
		return 1;
	return 0;
}

/*State decision algorithm 9.3.3 Fig 26*/
static UInteger8 
bmcStateDecision(MsgHeader *header, MsgAnnounce *announce,
		 const RunTimeOpts *rtOpts, PtpClock *ptpClock)
{
	Integer8 comp;
	Boolean newBM;
	
	newBM = ((memcmp(header->sourcePortIdentity.clockIdentity,
			    ptpClock->parentPortIdentity.clockIdentity,CLOCK_IDENTITY_LENGTH)) ||
		(header->sourcePortIdentity.portNumber != ptpClock->parentPortIdentity.portNumber));
	
	if (ptpClock->slaveOnly)	{
		s1(header,announce,ptpClock, rtOpts);
		if (newBM) {
			displayPortIdentity(&header->sourcePortIdentity,
					    "New best master selected:");
			ptpClock->counters.masterChanges++;
			if (ptpClock->portState == PTP_SLAVE)
				displayStatus(ptpClock, "State: ");
#ifdef PTPD_STATISTICS
				if(rtOpts->calibrationDelay) {
					ptpClock->isCalibrated = FALSE;
					ptpClock->statsUpdates = 0;
				}
#endif /* PTPD_STATISTICS */
		}
		return PTP_SLAVE;
	}

	if ((!ptpClock->number_foreign_records) && 
	    (ptpClock->portState == PTP_LISTENING))
		return PTP_LISTENING;

	copyD0(&ptpClock->msgTmpHeader,&ptpClock->msgTmp.announce,ptpClock);

	DBGV("local clockQuality.clockClass: %d \n", ptpClock->clockQuality.clockClass);

	comp = bmcDataSetComparison(&ptpClock->msgTmpHeader, &ptpClock->msgTmp.announce, header, announce, ptpClock, rtOpts);
	if (ptpClock->clockQuality.clockClass < 128) {
		if (comp < 0) {
			m1(rtOpts, ptpClock);
			return PTP_MASTER;
		} else if (comp > 0) {
			s1(header,announce,ptpClock, rtOpts);
			if (newBM) {
				displayPortIdentity(&header->sourcePortIdentity,
						    "New best master selected:");
				ptpClock->counters.masterChanges++;
				if(ptpClock->portState == PTP_PASSIVE)
					displayStatus(ptpClock, "State: ");
			}
			return PTP_PASSIVE;
		} else {
			DBG("Error in bmcDataSetComparison..\n");
		}
	} else {
		if (comp < 0) {
			m1(rtOpts,ptpClock);
			return PTP_MASTER;
		} else if (comp > 0) {
			s1(header,announce,ptpClock, rtOpts);
			if (newBM) {
				displayPortIdentity(&header->sourcePortIdentity,
						    "New best master selected:");
				ptpClock->counters.masterChanges++;
				if(ptpClock->portState == PTP_SLAVE)
					displayStatus(ptpClock, "State: ");
#ifdef PTPD_STATISTICS
				if(rtOpts->calibrationDelay) {
					ptpClock->isCalibrated = FALSE;
					ptpClock->statsUpdates = 0;
				}
#endif /* PTPD_STATISTICS */
			}
			return PTP_SLAVE;
		} else {
			DBG("Error in bmcDataSetComparison..\n");
		}
	}

	ptpClock->counters.protocolErrors++;
	/*  MB: Is this the return code below correct? */
	/*  Anyway, it's a valid return code. */

	return PTP_FAULTY;
}



UInteger8 
bmc(ForeignMasterRecord *foreignMaster,
    const RunTimeOpts *rtOpts, PtpClock *ptpClock)
{
	Integer16 i,best;

	DBGV("number_foreign_records : %d \n", ptpClock->number_foreign_records);
	if (!ptpClock->number_foreign_records)
		if (ptpClock->portState == PTP_MASTER)	{
			m1(rtOpts,ptpClock);
			return ptpClock->portState;
		}

	for (i=1,best = 0; i<ptpClock->number_foreign_records;i++)
		if ((bmcDataSetComparison(&foreignMaster[i].header,
					  &foreignMaster[i].announce,
					  &foreignMaster[best].header,
					  &foreignMaster[best].announce,
					  ptpClock, rtOpts)) < 0)
			best = i;

	DBGV("Best record : %d \n",best);
	ptpClock->foreign_record_best = best;

	return (bmcStateDecision(&foreignMaster[best].header,
				 &foreignMaster[best].announce,
				 rtOpts,ptpClock));
}



/*

13.3.2.6, page 126

PTPv2 valid flags per packet type:

ALL:
   .... .0.. .... .... = PTP_UNICAST
SYNC+Pdelay Resp:
   .... ..0. .... .... = PTP_TWO_STEP

Announce only:
   .... .... ..0. .... = FREQUENCY_TRACEABLE
   .... .... ...0 .... = TIME_TRACEABLE
   .... .... .... 0... = PTP_TIMESCALE
   .... .... .... .0.. = PTP_UTC_REASONABLE
   .... .... .... ..0. = PTP_LI_59
   .... .... .... ...0 = PTP_LI_61

*/
