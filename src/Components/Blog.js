import React from 'react'
import Card from '@material-ui/core/Card';
import Grid from '@material-ui/core/Grid'
import CardHeader from '@material-ui/core/CardHeader';
import CardMedia from '@material-ui/core/CardMedia';
import CardContent from '@material-ui/core/CardContent';

const style = {
    "padding-bottom": '25px',
    'text-decoration': 'none',
    card: {
        maxWidth: 400,
      },
      media: {
        height: 0,
        paddingTop: '56.25%', // 16:9
      },
      actions: {
        display: 'flex',
      },
      blog: {
        "padding-bottom": '25px',
      },
  }


const Blog = (props) => (
    <div className="blog" style={style}>
        { /* console.log(props) */}
        <a href={props.blog.link}>
        <Card > 
            {/*console.log(props.blog) */}
            <h3>{props.blog.title}</h3>
            <p>Categories: {props.blog.categories.map(cat => cat)}</p>
        </Card>
        </a>
    </div>
)

export default Blog