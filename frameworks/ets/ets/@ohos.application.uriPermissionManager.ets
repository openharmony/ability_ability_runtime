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
import AsyncCallbackWrapper from './utils/AbilityUtils';

export default namespace uriPermissionManager {
    loadLibraryWithPermissionCheck("uri_permission_manager_ani_kit.z", "@ohos.application.uriPermissionManager");

    export native function grantUriPermissionCallbackSync(uri: string, flag: wantConstant.Flags,
        targetBundleName: string, appCloneIndex: int, callback: AsyncCallbackWrapper<void>): void;
    export native function revokeUriPermissionCallbackSync(uri: string, targetBundleName: string, appCloneIndex: int,
        callback: AsyncCallbackWrapper<void>): void;
    export native function grantUriPermissionByKeyCallbackSync(uri: string, flag: wantConstant.Flags, targetTokenId: int,
        callback: AsyncCallbackWrapper<number>): void;
    export native function grantUriPermissionByKeyAsCallerCallbackSync(uri: string, flag: wantConstant.Flags, callerTokenId: int,
        targetTokenId: int, callback: AsyncCallbackWrapper<number>): void;

    export function grantUriPermission(uri: string, flag: wantConstant.Flags,targetBundleName: string): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data: undefined)=>void,
            reject:(err: BusinessError | null)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.grantUriPermissionCallbackSync(uri, flag, targetBundleName, 0, myCall);
            });
        });
        return p;
    }

    export function grantUriPermission(uri: string, flag: wantConstant.Flags, targetBundleName: string,
        appCloneIndex: int): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void,
            reject:(err: BusinessError | null)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.grantUriPermissionCallbackSync(uri,
                    flag, targetBundleName, appCloneIndex, myCall);
            });
        });
        return p;
    }

    export function grantUriPermission(uri: string, flag: wantConstant.Flags, targetBundleName: string,
        callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            uriPermissionManager.grantUriPermissionCallbackSync(uri, flag, targetBundleName, 0, myCall);
        })
    }

    export function revokeUriPermission(uri: string, targetBundleName: string): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data: undefined)=>void,
            reject:(err: BusinessError | null)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.revokeUriPermissionCallbackSync(uri, targetBundleName, 0, myCall);
            });
        });
        return p;
    }

    export function revokeUriPermission(uri: string, targetBundleName: string, appCloneIndex: int): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void,
            reject:(err: BusinessError | null)=>void):void => {
            let myCall = new AsyncCallbackWrapper<void>((err: BusinessError | null)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.revokeUriPermissionCallbackSync(uri, targetBundleName, appCloneIndex, myCall);
            });
        });
        return p;
    }

    export function revokeUriPermission(uri: string, targetBundleName: string, callback: AsyncCallback<void>): void {
        let myCall = new AsyncCallbackWrapper<void>(callback);
        taskpool.execute((): void => {
            uriPermissionManager.revokeUriPermissionCallbackSync(uri, targetBundleName, 0, myCall);
        })
    }

    export function grantUriPermissionByKey(key: string, flag: wantConstant.Flags, targetTokenId: int): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void, reject:(err:BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<number>((err: BusinessError | null, data: number | undefined)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.grantUriPermissionByKeyCallbackSync(key, flag, targetTokenId, myCall);
            });
        });
        return p;
    }

    export function grantUriPermissionByKeyAsCaller(key: string, flag: wantConstant.Flags, callerTokenId: int, targetTokenId: int): Promise<void> {
        let p:Promise<void> = new Promise<void>((resolve: (data:undefined)=>void,reject:(err:BusinessError)=>void):void => {
            let myCall = new AsyncCallbackWrapper<number>((err: BusinessError | null, data: number | undefined)=>{
                if (err === null || err.code === 0) {
                    resolve(undefined);
                } else {
                    reject(err);
                }
            });
            taskpool.execute((): void => {
                uriPermissionManager.grantUriPermissionByKeyAsCallerCallbackSync(key, flag, callerTokenId, targetTokenId, myCall);
            });
        });
        return p;
    }
}