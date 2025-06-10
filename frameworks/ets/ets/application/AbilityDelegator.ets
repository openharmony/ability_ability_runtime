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

import { AbilityMonitor } from 'application.AbilityMonitor';
import Want from '@ohos.app.ability.Want';
import Context from 'application.Context';
import { BusinessError, AsyncCallback } from '@ohos.base';
import { ShellCmdResult } from 'application.shellCmdResult';
import AsyncCallbackWrapper from '../utils/AbilityUtils';

export interface AbilityDelegator {
  printSync(msg: string): void;

  getAppContext(): Context;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void;

  finishTest(msg: string, code: number): Promise<void>;

  executeShellCommand(cmd: String, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: String, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: string, timeoutSecs?: number): Promise<ShellCmdResult>;

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void;

  addAbilityMonitor(monitor: AbilityMonitor): Promise<void>;

  startAbility(want: Want, callback: AsyncCallback<void>): void;

  startAbility(want: Want): Promise<void>;
}

class AbilityDelegatorInner implements AbilityDelegator {

  public native printSync(msg: string): void;

  public native getAppContext(): Context;

  public native nativeFinishTest(msg: String, code: number, callback: AsyncCallbackWrapper<void>): void;

  public native nativeExecuteShellCommand(cmd: string, timeoutSecs: number,
    callback: AsyncCallbackWrapper<ShellCmdResult>): void;

  public native nativeAddAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallbackWrapper<void>): void;

  public native nativeStartAbility(want: Want, callback: AsyncCallbackWrapper<void>): void;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeFinishTest(msg, code, myCall);
    });
  }
  finishTest(msg: string, code: number): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeFinishTest(msg, code, myCall);
        });
      });
    return p;
  }

  executeShellCommand(cmd: string, callback: AsyncCallback<ShellCmdResult, void>): void {
    let timeoutSecs = 0;
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.nativeExecuteShellCommand(cmd, timeoutSecs, myCall);
    });
  }
  executeShellCommand(cmd: string, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult, void>): void {
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.nativeExecuteShellCommand(cmd, timeoutSecs, myCall);
    });
  }
  executeShellCommand(cmd: string, timeoutSecs?: number): Promise<ShellCmdResult> {
    let p = new Promise<ShellCmdResult>((resolve: (data: ShellCmdResult) => void,
      reject: (err: BusinessError<void>) => void): void => {
      let myCall = new AsyncCallbackWrapper<ShellCmdResult>((err: BusinessError<void>, data: ShellCmdResult) => {
        if (err.code == 0) {
          resolve(data);
        } else {
          reject(err);
        }
      });
      taskpool.execute((): void => {
        if (timeoutSecs == null) {
          this.nativeExecuteShellCommand(cmd, 0, myCall);
        } else {
          this.nativeExecuteShellCommand(cmd, timeoutSecs as double, myCall);
        }
      });
    });
    return p;
  }

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeAddAbilityMonitor(monitor, myCall);
    });
  }
  addAbilityMonitor(monitor: AbilityMonitor): Promise<void> {
    let p =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeAddAbilityMonitor(monitor, myCall);
        });
      });
    return p;
  }

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.nativeStartAbility(want, myCall);
    });
  }
  startAbility(want: Want): Promise<void> {
    let p: Promise<void> =
      new Promise<void>((resolve: (data: undefined) => void, reject: (err: BusinessError<void>) => void): void => {
        let myCall = new AsyncCallbackWrapper<void>((err: BusinessError<void>) => {
          if (err.code == 0) {
            resolve(undefined);
          } else {
            reject(err);
          }
        });
        taskpool.execute((): void => {
          this.nativeStartAbility(want, myCall);
        });
      });
    return p;
  }

}
