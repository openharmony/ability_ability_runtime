/*
 * Copyright (c) 2025 Huawei Device Co., Ltd.
 * Licensed under the Apache License, Version 2.0 (the "License"),
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

import window from '@ohos.window';
import transfer from '@ohos.transfer';

type AbilityCallbackFn = (ability: Any) => void;
type WindowStageCallbackFn = (ability: Any, windowStage: window.WindowStage) => void;

interface InteropAbilityLifecycleCallback {
  onAbilityCreate: AbilityCallbackFn;
  onAbilityForeground: AbilityCallbackFn;
  onAbilityBackground: AbilityCallbackFn;
  onAbilityDestroy: AbilityCallbackFn;
  onWindowStageCreate: WindowStageCallbackFn;
  onWindowStageDestroy: WindowStageCallbackFn;
}

namespace InteropAbilityLifecycle {
  function onAbilityCreateInner(ability: ESValue, callback: InteropAbilityLifecycleCallback): void {
    callback.onAbilityCreate(ability.unwrap());
  };

  function onAbilityForegroundInner(ability: ESValue, callback: InteropAbilityLifecycleCallback): void {
    callback.onAbilityForeground(ability.unwrap());
  };

  function onAbilityBackgroundInner(ability: ESValue, callback: InteropAbilityLifecycleCallback): void {
    callback.onAbilityBackground(ability.unwrap());
  };

  function onAbilityDestroyInner(ability: ESValue, callback: InteropAbilityLifecycleCallback): void {
    callback.onAbilityDestroy(ability.unwrap());
  };

  function onWindowStageCreateInner(ability: ESValue, windowStage: ESValue,
    callback: InteropAbilityLifecycleCallback): void {
    callback.onWindowStageCreate(ability.unwrap(),
      transfer.transferStatic(windowStage.unwrap(), 'window.WindowStage') as window.WindowStage);
  };

  function onWindowStageDestroyInner(ability: ESValue, windowStage: ESValue,
    callback: InteropAbilityLifecycleCallback): void {
    callback.onWindowStageDestroy(ability.unwrap(),
      transfer.transferStatic(windowStage.unwrap(), 'window.WindowStage') as window.WindowStage);
  };
}

export default InteropAbilityLifecycleCallback;