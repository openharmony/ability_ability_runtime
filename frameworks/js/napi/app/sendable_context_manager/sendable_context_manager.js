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

const __sendableContextManager__ = requireInternal('app.ability.sendableContextManager');

class BusinessError extends Error {
  constructor(code) {
    let msg = '';
    if (errMap.has(code)) {
      msg = errMap.get(code);
    } else {
      msg = ERROR_MSG_INNER_ERROR;
    }
    super(msg);
    this.code = code;
  }
}

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
      throw new BusinessError(ERROR_CODE_INVALID_PARAM);
      return;
    }
    let eventHub = context.eventHub;
    if (eventHub === null || eventHub === undefined) {
      throw new BusinessError(ERROR_CODE_INVALID_PARAM);
      return;
    }
    if (!eventHub.setEventHubEmitMultiThreadingEnabled) {
      throw new BusinessError(ERROR_CODE_INVALID_PARAM);
      return;
    }
    eventHub.setEventHubEmitMultiThreadingEnabled(enable);
  }
};
  
export default sendableContextManager;