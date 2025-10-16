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

import Ability from '@ohos.app.ability.Ability';
import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import UIAbilityContext from 'application.UIAbilityContext';
import Want from '@ohos.app.ability.Want';
import window from '@ohos.window';
import rpc from '@ohos.rpc';
import { AbilityUtils } from './utils/AbilityUtils';
import { CalleeImpl } from './application/Callee';

export type OnReleaseCallback = (msg: string) => void;
export type OnRemoteStateChangeCallback = (msg: string) => void;
export type CalleeCallback = (indata: rpc.MessageSequence) => rpc.Parcelable;
export interface Caller {
  call(method: string, data: rpc.Parcelable): Promise<void>;
  callWithResult(method: string, data: rpc.Parcelable): Promise<rpc.MessageSequence>;
  release(): void;
  onRelease(callback: OnReleaseCallback): void;
  onRemoteStateChange(callback: OnRemoteStateChangeCallback): void;
  on(type: string, callback: OnReleaseCallback): void;
  offRelease(callback: OnReleaseCallback): void;
  offRelease(): void;
}
export interface Callee {
  on(method: string, callback: CalleeCallback): void;
  off(method: string): void;
}

export default class UIAbility extends Ability {
  private destroyCallbackPoint: long;
  private prepareToTerminateCallbackPointer: long;

  private native nativeOnDestroyCallback(): void;

  private native nativeOnPrepareToTerminateCallback(prepareTermination: boolean): void;

  private callOnDestroy(): boolean {
    let p = this.onDestroy();
    if (p instanceof Promise) {
      p.then(() => this.nativeOnDestroyCallback());
      return true;
    }
    return false;
  }

  private callOnPrepareToTerminateAsync(): boolean {
    const derivedClassType = AbilityUtils.getClassType(this);
    if (derivedClassType === undefined) {
      return false;
    }
    const uiAbilityClassType = AbilityUtils.getClassType(new UIAbility());
    if (uiAbilityClassType === undefined) {
      return false;
    }
    if (AbilityUtils.isOverride(derivedClassType, "onPrepareToTerminateAsync", uiAbilityClassType)) {
      this.onPrepareToTerminateAsync()
        .then((prepareTermination: boolean) => this.nativeOnPrepareToTerminateCallback(prepareTermination));
      return true;
    }
    return false;
  }

  context: UIAbilityContext = new UIAbilityContext();
  launchWant: Want = new Want();
  lastRequestWant: Want = new Want();
  callee: Callee = new CalleeImpl() as Callee;

  onCreate(want: Want, launchParam: AbilityConstant.LaunchParam): void {
  }

  onWindowStageCreate(windowStage: window.WindowStage): void {
  }

  onWindowStageWillDestroy(windowStage: window.WindowStage): void {
  }

  onWindowStageDestroy(): void {
  }

  onWindowStageRestore(windowStage: window.WindowStage): void {
  }

  onDestroy(): Promise<void> | undefined {
    return undefined;
  }

  onForeground(): void {
  }

  onWillForeground(): void {
  }

  onDidForeground(): void {
  }

  onBackground(): void {
  }

  onWillBackground(): void {
  }

  onDidBackground(): void {
  }


  onNewWant(want: Want, launchParam: AbilityConstant.LaunchParam): void {
  }

  onPrepareToTerminate(): boolean {
    return false;
  }

  onPrepareToTerminateAsync(): Promise<boolean> {
    return new Promise<boolean>((resolve: (a: boolean) => void,
      reject: (err: Error) => void): boolean => {
    });
  }

  onShare(wantParam: Record<string, Object>): void {
  }

  onCollaborate(wantParams: Record<string, Object>): AbilityConstant.CollaborateResult {
    return AbilityConstant.CollaborateResult.REJECT;
  }
}
