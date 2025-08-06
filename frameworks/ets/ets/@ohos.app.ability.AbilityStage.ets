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

import { Configuration } from '@ohos.app.ability.Configuration'
import AbilityStageContext from 'application.AbilityStageContext'
import Want from '@ohos.app.ability.Want';
import { AbilityUtils } from './utils/AbilityUtils';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';

export default class AbilityStage {
    context: AbilityStageContext = new AbilityStageContext();

    private prepareTerminationCallbackPoint: long;
    private native nativeOnPrepareTerminatePromiseCallback(): void;
    private callOnPrepareTermination(): boolean {
      const derivedClassType = AbilityUtils.getClassType(this);
      if (derivedClassType === undefined) {
          return false;
      }
      const classType = AbilityUtils.getClassType(new AbilityStage());
      if (classType === undefined) {
          return false;
      }
      if (AbilityUtils.isOverride(derivedClassType, "onPrepareTerminationAsync", classType)) {
          this.onPrepareTerminationAsync().then((data:AbilityConstant.PrepareTermination) => this.nativeOnPrepareTerminatePromiseCallback());
          return true;
      }
      return false;
    }

    onConfigurationUpdate(newConfig: Configuration): void {
    }

    onCreate(): void {
    }

    onDestroy(): void {
    }

  private acceptCallbackPoint: long;
  private native nativeOnAcceptWantCallback(result: string): void;
  private callOnAcceptWant(want: Want): boolean {
    const derivedClassType = AbilityUtils.getClassType(this);
    if (derivedClassType === undefined) {
      return false;
    }
    const classType = AbilityUtils.getClassType(new AbilityStage());
    if (classType === undefined) {
      return false;
    }
    if (AbilityUtils.isOverride(derivedClassType, 'onAcceptWantAsync', classType)) {
      this.onAcceptWantAsync(want).then((result:string) => this.nativeOnAcceptWantCallback(result));
      return true;
    }
    return false;
  }
  onAcceptWant(want: Want): string {
    return '';
  }
  async onAcceptWantAsync(want: Want): Promise<string> {
    return '';
  }

  private newProcessRequestCallbackPoint: long;
  private native nativeOnNewProcessRequestCallback(result: string): void;
  private callOnNewProcessRequest(want: Want): boolean {
    const derivedClassType = AbilityUtils.getClassType(this);
    if (derivedClassType === undefined) {
      return false;
    }
    const classType = AbilityUtils.getClassType(new AbilityStage());
    if (classType === undefined) {
      return false;
    }
    if (AbilityUtils.isOverride(derivedClassType, 'onNewProcessRequestAsync', classType)) {
      this.onNewProcessRequestAsync(want).then((result:string) => this.nativeOnNewProcessRequestCallback(result));
      return true;
    }
    return false;
  }
  onNewProcessRequest(want: Want): string {
    return '';
  }
  async onNewProcessRequestAsync(want: Want): Promise<string> {
    return '';
  }
  onPrepareTermination(): AbilityConstant.PrepareTermination {
    return AbilityConstant.PrepareTermination.CANCEL;
  }

  async onPrepareTerminationAsync(): Promise<AbilityConstant.PrepareTermination> {
    return AbilityConstant.PrepareTermination.CANCEL;
  }
}