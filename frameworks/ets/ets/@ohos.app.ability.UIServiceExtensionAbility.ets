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

import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import type Want from '@ohos.app.ability.Want';
import type UIServiceExtensionContext from 'application.UIServiceExtensionContext';
import type UIServiceHostProxy from 'application.UIServiceHostProxy';
import window from '@ohos.window';

export default class UIServiceExtensionAbility extends ExtensionAbility {

  context: UIServiceExtensionContext =  {};

  onCreate(want: Want): void {

  }

  onRequest(want: Want, startId: int): void {

  }

  onConnect(want: Want, proxy: UIServiceHostProxy): void {

  }

  onDisconnect(want: Want, proxy: UIServiceHostProxy): void {

  }

  onWindowWillCreate(config: window.ExtensionWindowConfig): void {

  }

  onWindowDidCreate(window: window.Window): void {

  }

  onData(proxy: UIServiceHostProxy, data: Record<string, Object>): void {

  }

  onDestroy(): void {

  }
}