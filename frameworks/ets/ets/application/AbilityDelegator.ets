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
import UIAbility from '@ohos.app.ability.UIAbility';
import AsyncCallbackWrapper from '../utils/AbilityUtils';

export interface AbilityDelegator {
  printSync(msg: string): void;

  getAppContext(): Context;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void;

  finishTest(msg: string, code: number): Promise<void>;

  executeShellCommand(cmd: String, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: String, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult>): void;

  executeShellCommand(cmd: string, timeoutSecs?: number): Promise<ShellCmdResult>;

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void

  addAbilityMonitor(monitor: AbilityMonitor): Promise<void>;

  startAbility(want: Want, callback: AsyncCallback<void>): void;

  startAbility(want: Want): Promise<void>;

  getCurrentTopAbility(callback: AsyncCallback<UIAbility>);

  getCurrentTopAbility(): Promise<UIAbility>;
}

class AbilityDelegatorInner implements AbilityDelegator {
  public native GetCurrentTopAbilitySync(): UIAbility;

  public native printSync(msg: string): void;

  public native getAppContext(): Context;

  public native finishTestSync(msg: String, code: number, callback: AsyncCallbackWrapper<void>): void;

  public native executeShellCommandsync(cmd: string, timeoutSecs: number,
    callback: AsyncCallbackWrapper<ShellCmdResult>): void;

  public native addAbilityMonitorAsync(monitor: AbilityMonitor, callback: AsyncCallbackWrapper<void>): void;

  public native startAbilityAsync(want: Want, callback: AsyncCallbackWrapper<void>): void;

  finishTest(msg: string, code: number, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.finishTestSync(msg, code, myCall);
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
          this.finishTestSync(msg, code, myCall);
        });
      });
    return p;
  }

  executeShellCommand(cmd: string, callback: AsyncCallback<ShellCmdResult, void>): void {
    let timeoutSecs = 0;
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.executeShellCommandsync(cmd, timeoutSecs, myCall);
    });
  }
  executeShellCommand(cmd: string, timeoutSecs: number, callback: AsyncCallback<ShellCmdResult, void>): void {
    let myCall = new AsyncCallbackWrapper<ShellCmdResult>(callback);
    taskpool.execute((): void => {
      this.executeShellCommandsync(cmd, timeoutSecs, myCall);
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
          this.executeShellCommandsync(cmd, 0, myCall);
        } else {
          this.executeShellCommandsync(cmd, timeoutSecs as double, myCall);
        }
      });
    });
    return p;
  }

  addAbilityMonitor(monitor: AbilityMonitor, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.addAbilityMonitorAsync(monitor, myCall);
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
          this.addAbilityMonitorAsync(monitor, myCall);
        });
      });
    return p;
  }

  startAbility(want: Want, callback: AsyncCallback<void>): void {
    let myCall = new AsyncCallbackWrapper<void>(callback);
    taskpool.execute((): void => {
      this.startAbilityAsync(want, myCall);
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
          this.startAbilityAsync(want, myCall);
        });
      });
    return p;
  }

  getCurrentTopAbility(callback: AsyncCallback<UIAbility>): void {
    let p = taskpool.execute((): UIAbility => {
      return this.GetCurrentTopAbilitySync()
    });
    console.log("getCurrentTopAbility callback2_04");
    p.then((e: NullishType) => {
      let ability = e as UIAbility;
      let resultCode: Int = 0;
      let error: BusinessError = { code: resultCode.intValue(), data: undefined };
      callback(error, ability);
      console.log("getCurrentTopAbility callback2_06");
    }).catch((err: BusinessError): void => {
      console.log("getCurrentTopAbility callback2_0606 err end");
      callback(err, {});
    });
  }
  getCurrentTopAbility(): Promise<UIAbility> {
    let p: Promise<UIAbility>  = new Promise<UIAbility>((resolve: (v: UIAbility) => void, reject: (error: Error) => void) => {
      console.log("getCurrentTopAbility promise1_01");
      let pPromise1 = taskpool.execute((): UIAbility => {
        return this.GetCurrentTopAbilitySync();
      });
      pPromise1.then((e: NullishType) => {
        console.log("getCurrentTopAbility promise1_04");
        let r: UIAbility = e as UIAbility;
        resolve(r);
      }).catch((err: BusinessError): void => {
        reject(err);
        console.log("getCurrentTopAbility promise1 end");
      });
    });
    return p;
  }
}
