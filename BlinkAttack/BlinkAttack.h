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

#ifndef _PRIME_BLINKATTACK_H
#define _PRIME_BLINKATTACK_H

#include <PLCTool/Attacks/Attack.h>
#include <PLCTool/PRIME/PrimeFrame.h>
#include <PLCTool/Topology/Adapter.h>
#include <PLCTool/gurux/include/enums.h>

#include <QDateTime>
#include <QObject>
#include <QTimer>
#include <vector>

namespace BlinkAttackPlugin {
class BlinkAttack : public PLCTool::Attack {
  Q_OBJECT

  enum State {
    IDLE,
    SEQUENCING,
    DISCONNECTING,
    CONNECTING,
    RELEASING,
    COMPLETED
  };

  enum State state;
  bool cancelled;

  int msTimeout;
  int msMessageWait = 1000;
  QTimer *timeoutTimer;
  QTimer *messageTimer;

  std::vector<uint8_t> sna;
  PLCTool::NodeId nid;
  PLCTool::ConnId lcid;
  int level;
  int serverAddress;
  int clientAddress;
  DLMS_AUTHENTICATION authenticationLevel;
  std::string password;
  bool isLogicalName;

  uint8_t pktId;
  uint8_t ackId;

  PLCTool::PrimeFrame *frame;

  PLCTool::StringParams endResult;

  void connectAll(void);

  void updateProgress(void);

  void composeAARQ(void);
  void composeDisconnect(void);
  void composeConnect(void);
  void composeRelease(void);

  void idToSna(PLCTool::NodeId id, uint8_t *sna);
  bool sequencingFound(void);
  bool isPacketExpected(unsigned char pktId);

  void transitionTo(State next);

public:
  BlinkAttack(QString const attackName, PLCTool::StringParams const &params,
              PLCTool::PrimeAdapter *adapter, QObject *parent = nullptr);

private slots:
  void onTimeout(void);
  void onMessageTime(void);

public slots:
  void onFrameReceived(PLCTool::Concentrator *, QDateTime, bool downlink,
                       const void *data, size_t size);
  void onDataReceived(PLCTool::Meter *meter, QDateTime timeStamp, bool downlink,
                      const void *data, size_t size);
  void onStart(void) override;
  void onCancel(void) override;
  void onEnd(void) override;
};
} // namespace BlinkAttackPlugin

#endif // _PRIME_BLINKATTACK_H
