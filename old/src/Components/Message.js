import React from 'react'
const Message = (props) => (
        <div>
            {console.log(props.message)} 
            <p>{props.message.message}</p>
        </div>

)

export default Message