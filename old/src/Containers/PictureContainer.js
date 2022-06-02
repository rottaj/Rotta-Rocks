import React from 'react'
import Gallery from 'react-photo-gallery'
import NavBar from '../Components/Navbar'
import BottomSocialNav from '../Components/bSocialNav'
const img1 = require('../IMG_0567.JPG')
const img2 = require('../IMG_0650.JPG')


export default class PictureContainer extends React.Component {
    
    /* popout the browser and maximize to see more columns! -> */
    photos = [
      {
        src: img1,
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/Dm-qxdynoEc/800x799",
        width: 1,
        height: 1
      },
      {
        src: img2,
        width: 3,
        height: 4
      },
      {
        src: "https://source.unsplash.com/iecJiKe_RNg/600x799",
        width: 3,
        height: 4
      },
      {
        src: "https://source.unsplash.com/epcsn8Ed8kY/600x799",
        width: 3,
        height: 4
      },
      {
        src: "https://source.unsplash.com/NQSWvyVRIJk/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/zh7GEuORbUw/600x799",
        width: 3,
        height: 4
      },
      {
        src: "https://source.unsplash.com/PpOHJezOalU/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/I1ASdgphUH4/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/XiDA78wAZVw/600x799",
        width: 3,
        height: 4
      },
      {
        src: "https://source.unsplash.com/x8xJpClTvR0/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/qGQNmBE7mYw/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/NuO6iTBkHxE/800x599",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/pF1ug8ysTtY/600x400",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/A-fubu9QJxE/800x533",
        width: 4,
        height: 3
      },
      {
        src: "https://source.unsplash.com/5P91SF0zNsI/740x494",
        width: 4,
        height: 3
      }
    ];

    styles = {
      header: {
        width: '100%'
      },
      main: {
        'margin': '5%',
        'margin-top': '10%'
      }
    }
    
      render() {
          return (
            <div style={this.styles.header}>
            <NavBar/>
            <div style={this.styles.main}>
              <Gallery photos={this.photos} direction={"column"} />
            </div>
            <BottomSocialNav/>
            </div>
          )
      }
}