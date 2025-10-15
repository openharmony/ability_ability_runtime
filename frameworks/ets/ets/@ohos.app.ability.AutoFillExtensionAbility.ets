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

import ExtensionAbility from '@ohos.app.ability.ExtensionAbility';
import UIExtensionContentSession from '@ohos.app.ability.UIExtensionContentSession';
import AutoFillExtensionContext from 'application.AutoFillExtensionContext';
import { FillRequest, SaveRequest, UpdateRequest, FillRequestCallback, SaveRequestCallback } from 'application.AutoFillRequest';
import { AbilityUtils } from './utils/AbilityUtils';

export default class AutoFillExtensionAbility extends ExtensionAbility {
  context!: AutoFillExtensionContext;

  onCreate(): void {

  }

  onFillRequest(session: UIExtensionContentSession, request: FillRequest, callback: FillRequestCallback): void {

  }

  onSaveRequest(session: UIExtensionContentSession, request: SaveRequest, callback: SaveRequestCallback): void {

  }

  onUpdateRequest(request: UpdateRequest): void {

  }

  onSessionDestroy(session: UIExtensionContentSession): void {

  }

  onForeground(): void {

  }

  onBackground(): void {

  }

  private destroyCallbackPoint: long;
  private native nativeOnDestroyCallback(): void;
  private callOnDestroy(): boolean {
    let p = this.onDestroy();
    if (p instanceof Promise) {
      p.then(() => this.nativeOnDestroyCallback());
      return true;
    }
    return false;
  }

  onDestroy(): Promise<void> | undefined {
    return undefined;
  }
}