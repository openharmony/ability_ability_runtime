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

import wantConstant from '@ohos.app.ability.wantConstant';
import { BusinessError, AsyncCallback } from '@ohos.base';

export class AsyncCallbackWrapper<T> {
  myFun_:AsyncCallback<T, void> = (err: BusinessError<void>, data: T) => {}

  constructor(myFun:AsyncCallback<T, void>){
    this.myFun_ = myFun;
  }

  invoke(err: BusinessError<void>, data: T) : void {
    this.myFun_(err, data);
  }
}

export default namespace uriPermissionManager {
    loadLibrary("uri_permission_manager_ani_kit.z");

    export native function grantUriPermissionPromiseSync(uri: string, flag: wantConstant.Flags, targetBundleName: string): int;
    export native function grantUriPermissionPromiseWithAppCloneIndexSync(uri: string, flag: wantConstant.Flags,
        targetBundleName: string, appCloneIndex: int): void;
    export native function grantUriPermissionCallbackSync(uri: string, flag: wantConstant.Flags, targetBundleName: string,
        callback: AsyncCallbackWrapper<number>): void;
    export native function revokeUriPermissionPromiseSync(uri: string, targetBundleName: string): int;
    export native function revokeUriPermissionPromiseWithAppCloneIndexSync(uri: string, targetBundleName: string,
        appCloneIndex: int): void;
    export native function revokeUriPermissionCallbackSync(uri: string, targetBundleName: string,
        callback: AsyncCallbackWrapper<number>): void;

    export function grantUriPermission(uri: string, flag: wantConstant.Flags, targetBundleName: string): Promise<int> {
        let p = new Promise<int>((resolve: (a: int) => void): void => {
            let p1 = launch uriPermissionManager.grantUriPermissionPromiseSync(uri, flag, targetBundleName);
            p1.then<int>((v: int): void => {
                resolve(v);
            });
        });
        return p;
    }

    export function grantUriPermission(uri: string, flag: wantConstant.Flags, targetBundleName: string,
        appCloneIndex: int): Promise<void> {
        let p = new Promise<void>((resolve: (a: int) => void): void => {
            let p1 = launch uriPermissionManager.grantUriPermissionPromiseWithAppCloneIndexSync(uri,
                flag, targetBundleName, appCloneIndex);
            p1.then<void>((): void => {
                resolve(1);
            });
        });
        return p;
    }

    export function grantUriPermission(uri: string, flag: wantConstant.Flags, targetBundleName: string,
        callback: AsyncCallback<number, void>): void {
        let myCall = new AsyncCallbackWrapper<number>(callback);
        let p1 = launch uriPermissionManager.grantUriPermissionCallbackSync(uri, flag, targetBundleName, myCall);
    }

    export function revokeUriPermission(uri: string, targetBundleName: string): Promise<int> {
        let p = new Promise<int>((resolve: (a: int) => void): void => {
            let p1 = launch uriPermissionManager.revokeUriPermissionPromiseSync(uri, targetBundleName);
            p1.then<int>((v: int): void => {
                resolve(v);
            });
        });
        return p;
    }

    export function revokeUriPermission(uri: string, targetBundleName: string, appCloneIndex: int): Promise<int> {
        let p = new Promise<int>((resolve: (a: int) => void): void => {
            let p1 = launch uriPermissionManager.revokeUriPermissionPromiseWithAppCloneIndexSync(uri, targetBundleName,
                appCloneIndex);
            p1.then<void>((): void => {
                resolve(1);
            });
        });
        return p;
    }

    export function revokeUriPermission(uri: string, targetBundleName: string, callback: AsyncCallback<number, void>): void {
        let myCall = new AsyncCallbackWrapper<number>(callback);
        let p1 = launch uriPermissionManager.revokeUriPermissionCallbackSync(uri, targetBundleName, myCall);
    }
 }