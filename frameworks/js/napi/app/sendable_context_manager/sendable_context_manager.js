/* 
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

let hilog = requireNapi('hilog');
const __sendableContextManager__ = requireInternal('app.ability.sendableContextManager');

let domainID = 0xD001320;
let TAG = 'JSENV';

let sendableContextManager = {
  convertFromContext: function (context) {
    return __sendableContextManager__.convertFromContext(context);
  },
  convertToContext: function (sendableContext) {
    return __sendableContextManager__.convertToContext(sendableContext);
  },
  convertToApplicationContext: function (sendableContext) {
    return __sendableContextManager__.convertToApplicationContext(sendableContext);
  },
  convertToAbilityStageContext: function (sendableContext) {
    return __sendableContextManager__.convertToAbilityStageContext(sendableContext);
  },
  convertToUIAbilityContext: function (sendableContext) {
    return __sendableContextManager__.convertToUIAbilityContext(sendableContext);
  },
  setEventHubMultithreadingEnabled: function (context, enable) {
    if (context === null || context === undefined) {
      hilog.sLogE(domainID, TAG, 'context is null.');
      return;
    }
    let eventHub = context.eventHub;
    if (eventHub === null || eventHub === undefined) {
      hilog.sLogE(domainID, TAG, 'eventHub is null.');
      return;
    }
    if (!eventHub.setEventHubOnMultiThreadingEnabled) {
      hilog.sLogE(domainID, TAG, 'eventHub.setEventHubOnMultiThreadingEnabled is null.');
      return;
    }
    if (!eventHub.setEventHubEmitMultiThreadingEnabled) {
      hilog.sLogE(domainID, TAG, 'eventHub.setEventHubEmitMultiThreadingEnabled is null.');
      return;
    }
    eventHub.setEventHubOnMultiThreadingEnabled(enable);
    eventHub.setEventHubEmitMultiThreadingEnabled(enable);
  }
};
  
export default sendableContextManager;