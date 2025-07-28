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

import insightIntentDriver from '@ohos.app.ability.insightIntentDriver';
import base from '@ohos.base'
import hilog from '@ohos.hilog';
import application from '@ohos.app.ability.application';
import { jsClone } from './format';
import bundle from '@ohos.bundle.bundleManager'
import image from '@ohos.multimedia.image';
import common from '@ohos.app.ability.common';

export interface ItemInfo {
  title: string,
  brief: string
}

export interface IntentInfo extends insightIntentDriver.InsightIntentInfo {
  bundleNameCN: string,
  iconImg: image.PixelMap | ResourceStr | DrawableDescriptor | undefined
}

export interface IntentGrout {
  string: IntentInfo[]
}

@Component
export struct IntentContent {
  @Consume('articlePathStack') articlePathStack: NavPathStack;
  scroller: Scroller = new Scroller();
  @State listMaterial: IntentInfo[] | null = null
  @State groupMaterial1: Record<string, IntentInfo[]> = {}
  @State groupMaterial: Record<string, IntentInfo[]> = {}
  context = this.getUIContext().getHostContext();
  @State pixelMap: image.PixelMap | ResourceStr | DrawableDescriptor | undefined = undefined;

  aboutToAppear() {
    this.getInfos()
  }

  onBackPress() {
    let context = AppStorage.get('context') as common.UIAbilityContext;
    context.terminateSelf();
  }

  async getInfos() {
    try {
      insightIntentDriver.getAllInsightIntentInfo(insightIntentDriver.GetInsightIntentFlag.GET_FULL_INSIGHT_INTENT)
        .then((data) => {
          this.listMaterial = data as IntentInfo[];
          this.groupMaterial1 = this.listMaterial.reduce((acc, item) => {
            const bundleName: string = item.bundleName;
            if (!acc[bundleName]) {
              acc[bundleName] = [];
            }
            acc[bundleName].push(item);
            return acc;
          }, {} as Record<string, IntentInfo[]>)

          Object.keys(this.groupMaterial1).forEach((bundleName: string, index: number) => {

            bundle.getApplicationInfo(bundleName, 0).then((resault) => {
              if (resault.debug) {
                Object.keys(this.groupMaterial1[bundleName]).forEach((key: string, index: number) => {
                  this.getAllIntentIcon(this.groupMaterial1[bundleName][key]['icon'], bundleName).then((value) => {
                    this.groupMaterial1[bundleName][key]['iconImg'] = value;
                    this.setAppName(this.groupMaterial1[bundleName][0]).then((value) => {
                      this.groupMaterial[value] = this.groupMaterial1[bundleName]
                    })
                  })
                })
              }
            })

            if (index === Object.keys(this.groupMaterial1).length - 1) {
              this.groupMaterial = jsClone(this.groupMaterial);
            }
          })
        })
        .catch((err: base.BusinessError) => {
          hilog.info(0x0000, 'testTag', 'getAllInsightIntentInfo errCode: %{public}d', err.code);
          hilog.info(0x0000, 'testTag', 'getAllInsightIntentInfo errMessage: %{public}s', err.message);
        });
    } catch (error) {
      hilog.error(0x0000, 'testTag', 'getAllInsightIntentInfo error caught %{public}s', JSON.stringify(error));
    }
  }

  async setAppName(intentDetail: IntentInfo): Promise<string> {
    let bundleName: string = intentDetail.bundleName;
    let moduleName: string = intentDetail.moduleName;
    let context = this.getUIContext().getHostContext();

    const bundleContext: Context = await application.createModuleContext(context, bundleName, moduleName);
    const bundleNameCN: string = bundleContext.resourceManager.getStringSync(bundleContext.applicationInfo.labelId);
    return bundleNameCN;
  }

  @Builder
  IntentBlock(domainType: string, material: IntentInfo[]) {
    Column() {
      Text(domainType)
        .fontFamily('HarmonyHeiTi-Medium')
        .fontSize(16)
        .fontWeight(500)
        .fontColor('#67686A')
        .margin({ left: 10, bottom: 8 })
        .textAlign(TextAlign.Start)
        .width('100%')

      List({ space: 12 }) {
        ForEach(material, (item: IntentInfo, index: number) => {
          ListItem() {
            this.IntentBlockLine(item)
          }
          .onClick(() => {
            this.articlePathStack.replacePath({ name: 'intentDetail', param: item });
          })
        }, (item: IntentInfo, index: number) => item.intentName)
      }
      .backgroundColor($r('app.color.background_list'))
      .borderRadius(16)
      .padding({
        top: 4,
        left: 12,
        right: 12,
        bottom: 4
      })
      .divider({
        strokeWidth: 0.5,
        startMargin: 38,
        endMargin: 0,
        color: $r('app.color.border_color_02')
      })

    }
    .width('100%')
    .margin({ top: 10, bottom: 18 })
    .alignItems(HorizontalAlign.Center)
  }

  async getAllIntentIcon(icon: string,
    bundleName: string): Promise<PixelMap | ResourceStr | DrawableDescriptor | undefined> {
    let pixelMap: image.PixelMap | ResourceStr | DrawableDescriptor | undefined = undefined;
    let resourceName2:string='';
    if (icon.startsWith('$r')) {
      try {
        let resourceStr: string | undefined = icon.match(/['"](.+)['"]/)?.[1];
        if (!resourceStr) {
          return icon;
        }
        let resourceName: string | undefined = resourceStr.split('.').pop();
        resourceName2 = resourceName as string;
        if (!resourceStr) {
          return icon;
        }
        let context = this.getUIContext().getHostContext();

        const bundleContext = await application.createBundleContext(context, bundleName);
        const valuePromise: Promise<Uint8Array> = bundleContext.resourceManager.getMediaByName(resourceName);
        const value: Uint8Array = await valuePromise;
        pixelMap = await this.uint8ArrayToImage(value);

      } catch (err) {
        return pixelMap;
      }
    } else {
      return '';
    }
    return pixelMap;
  }

  async uint8ArrayToImage(buffer: Uint8Array): Promise<PixelMap> {
    const imageSource = image.createImageSource(buffer.buffer);
    const imgIcon = await this.getUint8Array(imageSource);
    imageSource.release();
    return imgIcon;
  }

  async getUint8Array(imageSource: image.ImageSource): Promise<PixelMap> {
    const imageIcon = await imageSource.createPixelMap({
      desiredSize: { width: 24, height: 24 }
    });
    return imageIcon;
  }

  @Builder
  IntentBlockLine(intentDetail: IntentInfo) {
    Row() {

      Image(intentDetail.iconImg ?? $r('app.media.defaultIcon'))
        .width(24)
        .height(24)
        .borderRadius(6)
        .clip(true)
        .objectFit(ImageFit.Auto)
        .alt($r('app.media.defaultIcon'))

      Column() {
        Text(intentDetail.displayName)
          .fontFamily('HarmonyHeiTi-Medium')
          .fontSize(16)
          .fontColor('#494947')
          .fontWeight(500)
          .margin({ bottom: 6 })
        Text(intentDetail.displayDescription)
          .fontFamily('HarmonyHeiTi')
          .fontSize(14)
          .fontWeight(400)
          .fontColor('#777775')
      }
      .alignItems(HorizontalAlign.Start)
      .margin({ left: 16 })

      Blank()
      Image($r('app.media.ic_arrow'))
        .width(12)
        .height(24)
    }
    .width('100%')
    .height(64)
    .alignItems(VerticalAlign.Center)
  }

  build() {
    Column() {
      Row() {
        Column() {
          Image($r('app.media.ic_arrow_left'))
            .width(8.68)
            .height(16.48)
            .opacity(0.6)
        }
        .width(40)
        .height(40)
        .borderRadius(20)
        .backgroundColor($r('app.color.btn_bg_005'))
        .justifyContent(FlexAlign.Center)

        Text($r('app.string.Cont_title_syyt'))
          .margin({ left: 8 })
          .fontSize(20)
          .fontWeight(700)
          .fontColor($r('app.color.font_color_09'))

      }
      .alignItems(VerticalAlign.Center)
      .width('100%')
      .height(56)
      .padding({
        top: 14.5,
        right: 16,
        left: 16,
        bottom: 14.5
      })
      .position({ top: 0, left: 0 })
      .zIndex(100)
      .backgroundColor($r('app.color.background_cont'))
      .onClick(() => {
        let context = AppStorage.get('context') as common.UIAbilityContext;
        context.terminateSelf();
      })

      Scroll(this.scroller) {
        Column() {

          ForEach(Object.keys(this.groupMaterial), (bundleNameCN: string) => {
            Text(JSON.stringify(this.groupMaterial.bundleNameCN))
            this.IntentBlock(bundleNameCN, this.groupMaterial[bundleNameCN])
          }, (bundleNameCN: string) => bundleNameCN)

        }
      }
      .align(Alignment.TopStart)
      .padding({
        top: 76,
        right: 20,
        left: 20,
        bottom: 20
      })
      .constraintSize({ minHeight: '100%' })
      .align(Alignment.TopStart)
      .edgeEffect(EdgeEffect.Spring)
      .scrollable(ScrollDirection.Vertical)
      .scrollBar(BarState.Off)
      .width('100%')
      .height('100%')
      .backgroundColor($r('app.color.background_cont'))
      .clip(true)
    }
    .width('100%')
    .height('100%')
    .padding({top:36})
    .backgroundColor($r('app.color.background_cont'))
  }
}

