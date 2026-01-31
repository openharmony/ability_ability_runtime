/*
 * Copyright (c) 2026 Huawei Device Co., Ltd.
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

import ConfigurationConstant from './@ohos.app.ability.ConfigurationConstant';

declare namespace systemConfiguration {
  type OnColorModeUpdatedFn = (colorMode : ConfigurationConstant.ColorMode) => void;
  type OnFontSizeScaleUpdatedFn = (fontSizeScale : double) => void;
  type OnFontWeightScaleUpdatedFn = (fontWeightScale : double) => void;
  type OnMCCUpdatedFn = (mcc : string) => void;
  type OnMNCUpdatedFn = (mnc : string) => void;
  type OnLanguageUpdatedFn = (language : string) => void;
  type OnFontIdUpdatedFn = (fontId : string) => void;
  type OnHasPointerDeviceUpdatedFn = (hasPointerDevice : boolean) => void;
  type OnLocaleUpdatedFn = (locale : string) => void;
  interface UpdatedCallback {  
    onColorModeUpdated?: OnColorModeUpdatedFn;
    onFontSizeScaleUpdated?: OnFontSizeScaleUpdatedFn;
    onFontWeightScaleUpdated?: OnFontWeightScaleUpdatedFn;
    onMCCUpdated?: OnMCCUpdatedFn;
    onMNCUpdated?: OnMNCUpdatedFn;
    onLanguageUpdated?: OnLanguageUpdatedFn;
    onFontIdUpdated?: OnFontIdUpdatedFn;
    onHasPointerDeviceUpdated?: OnHasPointerDeviceUpdatedFn;
    onLocaleUpdated?: OnLocaleUpdatedFn;
  }
}

class UpdatedCallbackInner implements systemConfiguration.UpdatedCallback {
    onColorModeUpdated?: systemConfiguration.OnColorModeUpdatedFn = (colorMode : ConfigurationConstant.ColorMode) => {}
    onFontSizeScaleUpdated?: systemConfiguration.OnFontSizeScaleUpdatedFn = (fontSizeScale : double) => {}
    onFontWeightScaleUpdated?: systemConfiguration.OnFontWeightScaleUpdatedFn = (fontWeightScale : double)=> {}
    onMCCUpdated?: systemConfiguration.OnMCCUpdatedFn = (mcc : string) => {}
    onMNCUpdated?: systemConfiguration.OnMNCUpdatedFn = (mcc : string) => {}
    onLanguageUpdated?: systemConfiguration.OnLanguageUpdatedFn  = (language : string) => {}
    onFontIdUpdated?: systemConfiguration.OnFontIdUpdatedFn= (fontId : string) => {}
    onHasPointerDeviceUpdated?: systemConfiguration.OnHasPointerDeviceUpdatedFn = (hasPointerDevice : boolean) => {}
    onLocaleUpdated?: systemConfiguration.OnLocaleUpdatedFn = (locale : string) => {}
}

export default systemConfiguration;