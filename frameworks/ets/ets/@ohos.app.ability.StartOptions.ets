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

import contextConstant from '@ohos.app.ability.contextConstant';
import image from '@ohos.multimedia.image';
import bundleManager from '@ohos.bundle.bundleManager';

export default class StartOptions {
    windowMode?: number;
    displayId?: number;
    withAnimation?: boolean;
    windowLeft?: number;
    windowTop?: number;
    windowWidth?: number;
    windowHeight?: number;
    windowFocused?: boolean;
    processMode?: contextConstant.ProcessMode;
    startupVisibility?: contextConstant.StartupVisibility;
    startWindowBackgroundColor?: string;
    startWindowIcon?: image.PixelMap;
    supportWindowModes?: Array<bundleManager.SupportWindowMode>;
    minWindowWidth?: number;
    minWindowHeight?: number;
    maxWindowWidth?: number;
    maxWindowHeight?: number;
}