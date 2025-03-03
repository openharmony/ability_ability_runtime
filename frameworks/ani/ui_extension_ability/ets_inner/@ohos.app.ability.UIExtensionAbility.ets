import AbilityConstant from '@ohos.app.ability.AbilityConstant';
import Want from '@ohos.@ohos.app.ability.Want';

class UIExtensionContentSession {}

class UIExtensionContext{}

class ExtensionAbility {}

export class UIExtensionAbility extends ExtensionAbility {

  public native UIExtensionContext:long = 0;
  public native dotest() : void;

  onCreate(launchParam: AbilityConstant.LaunchParam): void {}

  onSessionCreate(want: Want, session: UIExtensionContentSession): void {}

  onSessionDestroy(session: UIExtensionContentSession): void {}

  onForeground(): void {}

  onBackground(): void {}

  //onDestroy(): void | Promise<void>;
  onDestroy(): void;
}

function main(){
  console.log("my test start")
  let cc = new UIExtensionAbility;
  cc.dotest()
  console.log("my test end")
}