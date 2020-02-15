const confirmRegisterEmailTemplate = (link) => {
  return `
  <heml>
    <head>
      <font href="https://vestrade.io/font.css" />
      <style>
      body {
        font-family: 'Space Grotesk', sans-serif;
        background-color: #1B105F;
        padding: 48px 0px;
      }
      container {
        width: 100%;
        max-width: 480px;
        padding: 16px 24px;
        background: #FFFFFF;
        box-shadow: 0px 12px 32px rgba(0, 0, 0, 0.12);
        border-radius: 4px;
      }
      button {
        font-family: 'Space Grotesk', sans-serif;
        padding: 8px 16px;
        font-style: normal;
        font-weight: 400;
        font-size: 16px;
        letter-spacing: .3px;
        line-height: 24px;
        text-align: center;
        background: #1B105F;
        box-shadow: 0px 8px 24px rgba(27, 16, 95, 0.3);
        border-radius: 4px;
      }
      </style>
    </head>
    <body>
      <container>
        <row style="margin-bottom: 8px">
          <col style="text-align: center">
            <img style="width:60px" src="https://vestrade-static.s3-ap-southeast-1.amazonaws.com/vestrade-blue.png" />
          </col>
        </row>
        <row style="margin-bottom: 8px">
          <p>Hi there,</p>
          <p>We received a request to set your Vestrade account. If this is correct, please confirm by clicking the button below:</p>
        </row>
        <button style="margin-bottom: 36px" href="${link}">Confirm Register</button>
        <row>
          <p>If you have any question, feel free to ask us on <a href="mailto:support@vestrade.io">support@vestrade.io</a></p>
        </row>
      </container>
    </body>
  </heml>
  `
}

module.exports = confirmRegisterEmailTemplate